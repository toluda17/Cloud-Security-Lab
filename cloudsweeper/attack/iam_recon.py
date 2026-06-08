"""
iam_recon.py - IAM reconnaissance simulation.
MITRE ATT&CK: T1087.004 (Account Discovery: Cloud Account)
Tactic: Discovery

This is usually one of the first things an attacker does after getting
hold of any AWS credentials. Before they try anything aggressive, they
want to know what they're working with: who else has access, what roles
exist, what permissions are attached, and whether there are any obvious
paths to escalate.

What this module does:
    - Lists all IAM users in the account
    - Lists all IAM roles (including trust policies, which show what can assume them)
    - Lists all IAM groups and their attached policies
    - Pulls the inline and managed policies attached to the target user
    - Checks for any directly attached admin-level policies

All of these are read-only API calls. They show up in CloudTrail under
eventSource: iam.amazonaws.com, and a burst of them from a single
identity in a short window is exactly what the recon detection rule
looks for.
"""

from botocore.exceptions import ClientError

from cloudsweeper.attack.ttp_base import TTP, TTPresult, TTPresultStatus
from cloudsweeper.config import config
from cloudsweeper.utils.aws_client import AWSClientFactory


class IAMRecon(TTP):
    """
    Simulates an attacker mapping out the IAM landscape of an AWS account.

    I target the SIM_TARGET_USER from config (DemoDev by default) and treat
    it as the initial compromised identity. The goal is to find out what that
    user can see, what roles exist, and whether there's an obvious next step
    for privilege escalation.
    """

    def __init__(self, run_id: str | None = None):
        super().__init__(run_id)
        self._iam = AWSClientFactory.get_client("iam")
        self._target = config.SIM_TARGET_USER

    @property
    def ttp_id(self) -> str:
        return "iam_recon"

    @property
    def mitre_id(self) -> str:
        return "T1087.004"

    @property
    def mitre_tactic(self) -> str:
        return "Discovery"

    def describe(self) -> str:
        return (
            "Simulates IAM account discovery, the read-only enumeration an attacker "
            "does right after getting credentials to understand the account structure. "
            "Makes ListUsers, ListRoles, ListGroups, ListAttachedUserPolicies, and "
            "ListUserPolicies calls against IAM. In CloudTrail these show up as a "
            "burst of iam.amazonaws.com read events from a single identity, which is "
            "the pattern the recon detection rule targets."
        )

    def execute(self) -> TTPresult:
        self._log_start(self._target)

        findings = []
        api_calls = []

        # --- 1. List all IAM users ---
        # An attacker wants to know every identity in the account.
        # More users = more potential targets for lateral movement.
        users = self._list_users(findings, api_calls)

        # --- 2. List all IAM roles ---
        # Roles are often more interesting than users because they can be
        # assumed cross-account or by services. Trust policies tell you
        # exactly who's allowed to assume each role.
        self._list_roles(findings, api_calls)

        # --- 3. List all IAM groups ---
        # Groups are how permissions are typically handed out in bulk.
        # Knowing the group structure tells you what permissions exist
        # and which users have them.
        self._list_groups(findings, api_calls)

        # --- 4. Enumerate the target user's own permissions ---
        # This is what the attacker actually cares about most: what can
        # *they* do with the credentials they have right now?
        self._enumerate_user_permissions(self._target, findings, api_calls)

        if not findings:
            return self._make_result(
                status=TTPresultStatus.FAILED,
                target=self._target,
                raw_api_calls=api_calls,
                error="No findings returned. Check that credentials are valid and IAM read permissions are available.",
            )

        status = TTPresultStatus.SUCCESS
        # If we got some findings but also hit permission errors, mark it partial.
        # That's still useful. The errors themselves tell us where the IAM boundary is.
        if any(f.get("type") == "permission_denied" for f in findings):
            status = TTPresultStatus.PARTIAL

        return self._make_result(
            status=status,
            target=self._target,
            findings=findings,
            raw_api_calls=api_calls,
        )

    # ------------------------------------------------------------------
    # Private helpers, one per enumeration step
    # ------------------------------------------------------------------

    def _list_users(self, findings: list, api_calls: list) -> list:
        """List every IAM user in the account."""
        api_calls.append("iam:ListUsers")
        try:
            paginator = self._iam.get_paginator("list_users")
            users = []
            for page in paginator.paginate():
                for user in page["Users"]:
                    users.append(user["UserName"])
                    findings.append({
                        "type": "iam_user_discovered",
                        "username": user["UserName"],
                        "user_id": user["UserId"],
                        "arn": user["Arn"],
                        "created": user["CreateDate"].isoformat(),
                        # PasswordLastUsed tells an attacker which accounts
                        # are active vs dormant
                        "password_last_used": (
                            user["PasswordLastUsed"].isoformat()
                            if "PasswordLastUsed" in user
                            else "never"
                        ),
                    })
                    self._log_finding("iam_user_discovered", user["UserName"])
            return users
        except ClientError as e:
            self._handle_error("iam:ListUsers", e, findings)
            return []

    def _list_roles(self, findings: list, api_calls: list) -> None:
        """List all IAM roles and capture their trust policies."""
        api_calls.append("iam:ListRoles")
        try:
            paginator = self._iam.get_paginator("list_roles")
            for page in paginator.paginate():
                for role in page["Roles"]:
                    finding = {
                        "type": "iam_role_discovered",
                        "role_name": role["RoleName"],
                        "arn": role["Arn"],
                        "created": role["CreateDate"].isoformat(),
                        # The trust policy is gold for an attacker. It tells
                        # them exactly who/what can assume this role
                        "trust_policy": role.get("AssumeRolePolicyDocument", {}),
                    }
                    findings.append(finding)
                    self._log_finding("iam_role_discovered", role["RoleName"])

                    # Flag any roles that look like they could be assumed by
                    # the target user or by any AWS service
                    self._check_assumable_role(role, findings, api_calls)

        except ClientError as e:
            self._handle_error("iam:ListRoles", e, findings)

    def _check_assumable_role(self, role: dict, findings: list, api_calls: list) -> None:
        """
        Check whether a role's trust policy allows assumption by any IAM
        user or broad service principal. These are the roles worth trying
        AssumeRole on in the privilege escalation phase.
        """
        api_calls.append("iam:GetRole")
        try:
            trust = role.get("AssumeRolePolicyDocument", {})
            for statement in trust.get("Statement", []):
                principal = statement.get("Principal", {})
                # AWS: "*" or a broad principal means anyone can assume it
                if principal == "*" or (
                    isinstance(principal, dict) and principal.get("AWS") == "*"
                ):
                    findings.append({
                        "type": "overly_permissive_trust_policy",
                        "role_name": role["RoleName"],
                        "arn": role["Arn"],
                        "detail": "Role trust policy allows assumption by any principal (*)",
                        "severity": "HIGH",
                    })
                    self._log_finding("overly_permissive_trust_policy", role["RoleName"])
        except Exception:
            # Trust policy parsing shouldn't crash the run
            pass

    def _list_groups(self, findings: list, api_calls: list) -> None:
        """List all IAM groups and the policies attached to each."""
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

                    # Pull the policies for each group to understand what
                    # permissions that group's members have
                    self._list_group_policies(group["GroupName"], findings, api_calls)

        except ClientError as e:
            self._handle_error("iam:ListGroups", e, findings)

    def _list_group_policies(self, group_name: str, findings: list, api_calls: list) -> None:
        """Get attached managed policies for a specific group."""
        api_calls.append("iam:ListAttachedGroupPolicies")
        try:
            response = self._iam.list_attached_group_policies(GroupName=group_name)
            for policy in response.get("AttachedPolicies", []):
                findings.append({
                    "type": "group_policy_discovered",
                    "group_name": group_name,
                    "policy_name": policy["PolicyName"],
                    "policy_arn": policy["PolicyArn"],
                    # Flag admin policies explicitly. These are the most
                    # interesting from an attacker's perspective
                    "is_admin_policy": "AdministratorAccess" in policy["PolicyName"],
                })
                self._log_finding("group_policy_discovered", f"{group_name}: {policy['PolicyName']}")
        except ClientError as e:
            self._handle_error("iam:ListAttachedGroupPolicies", e, findings)

    def _enumerate_user_permissions(
        self, username: str, findings: list, api_calls: list
    ) -> None:
        """
        Pull all policies attached to the target user, both managed and
        inline. This is what tells an attacker what they can actually do
        with the credentials they have.
        """
        # Managed policies attached directly to the user
        api_calls.append("iam:ListAttachedUserPolicies")
        try:
            response = self._iam.list_attached_user_policies(UserName=username)
            for policy in response.get("AttachedPolicies", []):
                findings.append({
                    "type": "user_managed_policy",
                    "username": username,
                    "policy_name": policy["PolicyName"],
                    "policy_arn": policy["PolicyArn"],
                    "is_admin_policy": "AdministratorAccess" in policy["PolicyName"],
                })
                self._log_finding("user_managed_policy", f"{username}: {policy['PolicyName']}")
        except ClientError as e:
            self._handle_error("iam:ListAttachedUserPolicies", e, findings)

        # Inline policies embedded directly in the user definition
        api_calls.append("iam:ListUserPolicies")
        try:
            response = self._iam.list_user_policies(UserName=username)
            for policy_name in response.get("PolicyNames", []):
                findings.append({
                    "type": "user_inline_policy",
                    "username": username,
                    "policy_name": policy_name,
                    # Inline policies are sometimes more permissive than
                    # managed ones because they're easier to overlook
                    "note": "inline policy, may not appear in standard IAM audits",
                })
                self._log_finding("user_inline_policy", f"{username}: {policy_name}")
        except ClientError as e:
            self._handle_error("iam:ListUserPolicies", e, findings)

        # Which groups is the target user a member of?
        # Group membership determines most of the effective permissions.
        api_calls.append("iam:ListGroupsForUser")
        try:
            response = self._iam.list_groups_for_user(UserName=username)
            for group in response.get("Groups", []):
                findings.append({
                    "type": "user_group_membership",
                    "username": username,
                    "group_name": group["GroupName"],
                    "group_arn": group["Arn"],
                })
                self._log_finding("user_group_membership", f"{username} in {group['GroupName']}")
        except ClientError as e:
            self._handle_error("iam:ListGroupsForUser", e, findings)

    def _handle_error(self, api_call: str, error: ClientError, findings: list) -> None:
        """
        Handle a ClientError without crashing the run. AccessDenied is
        actually a useful finding. It tells us where the IAM boundary is.
        Anything else gets logged as an unexpected error.
        """
        code = error.response["Error"]["Code"]
        if code in ("AccessDenied", "AccessDeniedException"):
            findings.append({
                "type": "permission_denied",
                "api_call": api_call,
                "detail": f"Access denied on {api_call}, which defines the IAM boundary for {self._target}",
            })
            self._logger.warning(
                f"Access denied on {api_call}, recording as a boundary finding",
                extra={"ttp_id": self.ttp_id, "api_call": api_call},
            )
        else:
            self._logger.error(
                f"Unexpected error on {api_call}",
                extra={"ttp_id": self.ttp_id, "api_call": api_call, "error": str(error)},
            )
