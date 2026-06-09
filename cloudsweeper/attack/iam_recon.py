"""
iam_recon.py - IAM reconnaissance simulation.
MITRE ATT&CK: T1087.004 (Account Discovery: Cloud Account)
Tactic: Discovery

This is usually the first thing an attacker does after getting hold of
AWS credentials. Before trying anything aggressive, they want to know
what they're working with: who else has access, what roles exist, what
permissions are attached, and whether there's an obvious path to escalate.

I list all users, roles, and groups in the account, then pull the
permissions attached to the target user specifically. All read-only
calls, nothing destructive.
"""

from botocore.exceptions import ClientError

from cloudsweeper.attack.ttp_base import TTP, TTPresult, TTPresultStatus
from cloudsweeper.config import config
from cloudsweeper.utils.aws_client import AWSClientFactory


class IAMRecon(TTP):

    def __init__(self, run_id=None):
        super().__init__(run_id)
        self._iam = AWSClientFactory.get_client("iam")
        self._target = config.SIM_TARGET_USER

    @property
    def ttp_id(self):
        return "iam_recon"

    @property
    def mitre_id(self):
        return "T1087.004"

    @property
    def mitre_tactic(self):
        return "Discovery"

    def describe(self):
        return (
            "Simulates IAM account discovery. Makes ListUsers, ListRoles, ListGroups, "
            "and policy enumeration calls to map out the account structure. In CloudTrail "
            "these show up as a burst of iam.amazonaws.com read events from a single "
            "identity, which is the pattern the recon detection rule looks for."
        )

    def execute(self):
        self._log_start(self._target)

        findings = []
        api_calls = []

        self._list_users(findings, api_calls)
        self._list_roles(findings, api_calls)
        self._list_groups(findings, api_calls)
        self._get_user_permissions(self._target, findings, api_calls)

        if not findings:
            return self._make_result(
                status=TTPresultStatus.FAILED,
                target=self._target,
                raw_api_calls=api_calls,
                error="No findings returned. Check credentials and IAM read permissions.",
            )

        status = TTPresultStatus.SUCCESS
        if any(f.get("type") == "permission_denied" for f in findings):
            status = TTPresultStatus.PARTIAL

        return self._make_result(
            status=status,
            target=self._target,
            findings=findings,
            raw_api_calls=api_calls,
        )

    def _list_users(self, findings, api_calls):
        """List every IAM user in the account."""
        api_calls.append("iam:ListUsers")
        try:
            paginator = self._iam.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page["Users"]:
                    findings.append({
                        "type": "iam_user_discovered",
                        "username": user["UserName"],
                        "arn": user["Arn"],
                        "created": user["CreateDate"].isoformat(),
                        # PasswordLastUsed tells me which accounts are active vs dormant
                        "password_last_used": (
                            user["PasswordLastUsed"].isoformat()
                            if "PasswordLastUsed" in user else "never"
                        ),
                    })
                    self._log_finding("iam_user_discovered", user["UserName"])
        except ClientError as e:
            self._handle_error("iam:ListUsers", e, findings)

    def _list_roles(self, findings, api_calls):
        """
        List all IAM roles. Roles are often more interesting than users
        because they can be assumed by services or other accounts.
        The trust policy tells me exactly who's allowed to assume each one.
        """
        api_calls.append("iam:ListRoles")
        try:
            paginator = self._iam.get_paginator("list_roles")
            for page in paginator.paginate():
                for role in page["Roles"]:
                    findings.append({
                        "type": "iam_role_discovered",
                        "role_name": role["RoleName"],
                        "arn": role["Arn"],
                        "created": role["CreateDate"].isoformat(),
                        "trust_policy": role.get("AssumeRolePolicyDocument", {}),
                    })
                    self._log_finding("iam_role_discovered", role["RoleName"])

                    # Flag roles with overly broad trust policies.
                    # Principal: * means anyone can assume this role, which is a problem.
                    trust = role.get("AssumeRolePolicyDocument", {})
                    for statement in trust.get("Statement", []):
                        principal = statement.get("Principal", {})
                        if principal == "*" or (
                            isinstance(principal, dict) and principal.get("AWS") == "*"
                        ):
                            findings.append({
                                "type": "overly_permissive_trust_policy",
                                "role_name": role["RoleName"],
                                "severity": "HIGH",
                                "detail": f"{role['RoleName']} can be assumed by anyone (*)",
                            })
                            self._log_finding("overly_permissive_trust_policy", role["RoleName"])

        except ClientError as e:
            self._handle_error("iam:ListRoles", e, findings)

    def _list_groups(self, findings, api_calls):
        """
        List all IAM groups and the policies attached to each.
        Groups are how permissions are usually handed out in bulk, so
        knowing the group structure tells me what access levels exist.
        """
        api_calls.append("iam:ListGroups")
        try:
            paginator = self._iam.get_paginator("list_groups")
            for page in paginator.paginate():
                for group in page["Groups"]:
                    findings.append({
                        "type": "iam_group_discovered",
                        "group_name": group["GroupName"],
                        "arn": group["Arn"],
                    })
                    self._log_finding("iam_group_discovered", group["GroupName"])

                    # Pull attached policies for each group
                    api_calls.append("iam:ListAttachedGroupPolicies")
                    try:
                        response = self._iam.list_attached_group_policies(
                            GroupName=group["GroupName"]
                        )
                        for policy in response.get("AttachedPolicies", []):
                            findings.append({
                                "type": "group_policy_discovered",
                                "group_name": group["GroupName"],
                                "policy_name": policy["PolicyName"],
                                "policy_arn": policy["PolicyArn"],
                                "is_admin": "AdministratorAccess" in policy["PolicyName"],
                            })
                            self._log_finding(
                                "group_policy_discovered",
                                f"{group['GroupName']}: {policy['PolicyName']}"
                            )
                    except ClientError as e:
                        self._handle_error("iam:ListAttachedGroupPolicies", e, findings)

        except ClientError as e:
            self._handle_error("iam:ListGroups", e, findings)

    def _get_user_permissions(self, username, findings, api_calls):
        """
        Pull all policies attached to the target user. This is what tells
        me what the compromised identity can actually do right now.
        """
        # Managed policies attached directly to the user
        api_calls.append("iam:ListAttachedUserPolicies")
        try:
            response = self._iam.list_attached_user_policies(UserName=username)
            for policy in response.get("AttachedPolicies", []):
                findings.append({
                    "type": "user_policy_discovered",
                    "username": username,
                    "policy_name": policy["PolicyName"],
                    "policy_arn": policy["PolicyArn"],
                    "is_admin": "AdministratorAccess" in policy["PolicyName"],
                })
                self._log_finding("user_policy_discovered", f"{username}: {policy['PolicyName']}")
        except ClientError as e:
            self._handle_error("iam:ListAttachedUserPolicies", e, findings)

        # Inline policies embedded in the user definition
        api_calls.append("iam:ListUserPolicies")
        try:
            response = self._iam.list_user_policies(UserName=username)
            for policy_name in response.get("PolicyNames", []):
                findings.append({
                    "type": "user_inline_policy",
                    "username": username,
                    "policy_name": policy_name,
                })
                self._log_finding("user_inline_policy", f"{username}: {policy_name}")
        except ClientError as e:
            self._handle_error("iam:ListUserPolicies", e, findings)

        # Which groups is the target user in?
        api_calls.append("iam:ListGroupsForUser")
        try:
            response = self._iam.list_groups_for_user(UserName=username)
            for group in response.get("Groups", []):
                findings.append({
                    "type": "user_group_membership",
                    "username": username,
                    "group_name": group["GroupName"],
                })
                self._log_finding("user_group_membership", f"{username} in {group['GroupName']}")
        except ClientError as e:
            self._handle_error("iam:ListGroupsForUser", e, findings)

    def _handle_error(self, api_call, error, findings):
        """
        AccessDenied is a finding, not a crash. It tells me where
        the IAM boundary is for this identity.
        """
        code = error.response["Error"]["Code"]
        if code in ("AccessDenied", "AccessDeniedException"):
            findings.append({
                "type": "permission_denied",
                "api_call": api_call,
                "detail": f"Access denied on {api_call}",
            })
            self._logger.warning(
                f"Access denied on {api_call}",
                extra={"ttp_id": self.ttp_id},
            )
        else:
            self._logger.error(
                f"Unexpected error on {api_call}: {error}",
                extra={"ttp_id": self.ttp_id},
            )
