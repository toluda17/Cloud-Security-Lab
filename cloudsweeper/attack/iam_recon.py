"""
iam_recon.py - IAM reconnaissance simulation.
MITRE ATT&CK: T1087.004 (Account Discovery: Cloud Account)
Tactic: Discovery

First thing an attacker does after getting credentials. They want to
know what they're working with: who else has access, what roles exist,
and what the target user can actually do.

All read-only calls, nothing destructive.
"""

from botocore.exceptions import ClientError
from cloudsweeper.attack.ttp_base import TTP, TTPresultStatus
from cloudsweeper.config import config
from cloudsweeper.utils.aws_client import AWSClientFactory


class IAMRecon(TTP):

    def __init__(self, run_id=None):
        super().__init__(run_id)
        self._iam = AWSClientFactory.get_client("iam")
        self._target = config.SIM_TARGET_USER

    @property
    def ttp_id(self): return "iam_recon"

    @property
    def mitre_id(self): return "T1087.004"

    @property
    def mitre_tactic(self): return "Discovery"

    def describe(self):
        return (
            "Lists all IAM users, roles, and groups, then pulls the permissions "
            "attached to the target user. Shows up in CloudTrail as a burst of "
            "iam.amazonaws.com read events from a single identity."
        )

    def execute(self):
        self._log_start(self._target)
        findings, api_calls = [], []

        self._list_users(findings, api_calls)
        self._list_roles(findings, api_calls)
        self._list_groups(findings, api_calls)
        self._get_user_permissions(findings, api_calls)

        if not findings:
            return self._make_result(TTPresultStatus.FAILED, self._target, raw_api_calls=api_calls,
                error="No findings. Check credentials and IAM read permissions.")

        status = TTPresultStatus.PARTIAL if any(f.get("type") == "permission_denied" for f in findings) else TTPresultStatus.SUCCESS
        return self._make_result(status, self._target, findings, api_calls)

    def _list_users(self, findings, api_calls):
        api_calls.append("iam:ListUsers")
        try:
            for page in self._iam.get_paginator("list_users").paginate():
                for user in page["Users"]:
                    findings.append({
                        "type": "iam_user_discovered",
                        "username": user["UserName"],
                        "arn": user["Arn"],
                        "password_last_used": user.get("PasswordLastUsed", "never"),
                    })
                    self._log_finding("iam_user_discovered", user["UserName"])
        except ClientError as e:
            self._handle_error("iam:ListUsers", e, findings)

    def _list_roles(self, findings, api_calls):
        api_calls.append("iam:ListRoles")
        try:
            for page in self._iam.get_paginator("list_roles").paginate():
                for role in page["Roles"]:
                    findings.append({
                        "type": "iam_role_discovered",
                        "role_name": role["RoleName"],
                        "arn": role["Arn"],
                        "trust_policy": role.get("AssumeRolePolicyDocument", {}),
                    })
                    self._log_finding("iam_role_discovered", role["RoleName"])

                    # Flag roles with wildcard trust policies
                    for stmt in role.get("AssumeRolePolicyDocument", {}).get("Statement", []):
                        if stmt.get("Principal") == "*":
                            findings.append({
                                "type": "overly_permissive_trust_policy",
                                "role_name": role["RoleName"],
                                "severity": "HIGH",
                            })
        except ClientError as e:
            self._handle_error("iam:ListRoles", e, findings)

    def _list_groups(self, findings, api_calls):
        api_calls.append("iam:ListGroups")
        try:
            for page in self._iam.get_paginator("list_groups").paginate():
                for group in page["Groups"]:
                    findings.append({"type": "iam_group_discovered", "group_name": group["GroupName"], "arn": group["Arn"]})
                    self._log_finding("iam_group_discovered", group["GroupName"])

                    api_calls.append("iam:ListAttachedGroupPolicies")
                    try:
                        resp = self._iam.list_attached_group_policies(GroupName=group["GroupName"])
                        for policy in resp.get("AttachedPolicies", []):
                            findings.append({
                                "type": "group_policy_discovered",
                                "group_name": group["GroupName"],
                                "policy_name": policy["PolicyName"],
                                "is_admin": "AdministratorAccess" in policy["PolicyName"],
                            })
                            self._log_finding("group_policy_discovered", f"{group['GroupName']}: {policy['PolicyName']}")
                    except ClientError as e:
                        self._handle_error("iam:ListAttachedGroupPolicies", e, findings)
        except ClientError as e:
            self._handle_error("iam:ListGroups", e, findings)

    def _get_user_permissions(self, findings, api_calls):
        """Pull all policies and group memberships for the target user."""
        for action, method, key in [
            ("iam:ListAttachedUserPolicies", lambda: self._iam.list_attached_user_policies(UserName=self._target), "AttachedPolicies"),
            ("iam:ListUserPolicies", lambda: self._iam.list_user_policies(UserName=self._target), "PolicyNames"),
            ("iam:ListGroupsForUser", lambda: self._iam.list_groups_for_user(UserName=self._target), "Groups"),
        ]:
            api_calls.append(action)
            try:
                resp = method()
                for item in resp.get(key, []):
                    if isinstance(item, dict):
                        name = item.get("PolicyName") or item.get("GroupName", "")
                        finding_type = "user_policy_discovered" if "Policy" in key else "user_group_membership"
                    else:
                        name = item
                        finding_type = "user_inline_policy"
                    findings.append({"type": finding_type, "username": self._target, "name": name})
                    self._log_finding(finding_type, f"{self._target}: {name}")
            except ClientError as e:
                self._handle_error(action, e, findings)

    def _handle_error(self, api_call, error, findings):
        code = error.response["Error"]["Code"]
        if code in ("AccessDenied", "AccessDeniedException"):
            findings.append({"type": "permission_denied", "api_call": api_call})
            self._logger.warning(f"Access denied on {api_call}", extra={"ttp_id": self.ttp_id})
        else:
            self._logger.error(f"Unexpected error on {api_call}: {error}", extra={"ttp_id": self.ttp_id})
