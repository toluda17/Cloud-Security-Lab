"""
privilege_escalation.py - Privilege escalation simulation.
MITRE ATT&CK: T1484.001 (Domain Policy Modification: PassRole abuse)
Tactic: Privilege Escalation

After recon, an attacker knows what roles exist. Now they try to move
to a more privileged identity using AssumeRole.

I scan all roles to find any whose trust policy might allow the target
identity to assume them, then actually try AssumeRole against each one.
If it works, I record it as a critical finding and discard the credentials.
Nothing destructive happens either way.
"""

from botocore.exceptions import ClientError
from cloudsweeper.attack.ttp_base import TTP, TTPresultStatus
from cloudsweeper.config import config
from cloudsweeper.utils.aws_client import AWSClientFactory


class PrivilegeEscalation(TTP):

    def __init__(self, run_id=None):
        super().__init__(run_id)
        self._iam = AWSClientFactory.get_client("iam")
        self._sts = AWSClientFactory.get_client("sts")
        self._target = config.SIM_TARGET_USER

    @property
    def ttp_id(self): return "privilege_escalation"

    @property
    def mitre_id(self): return "T1484.001"

    @property
    def mitre_tactic(self): return "Privilege Escalation"

    def describe(self):
        return (
            "Checks which roles the target identity could assume based on trust policies, "
            "then attempts sts:AssumeRole against each one. Shows up in CloudTrail as "
            "AssumeRole calls from a low-privilege identity."
        )

    def execute(self):
        self._log_start(self._target)
        findings, api_calls = [], []

        candidates = self._find_candidate_roles(findings, api_calls)
        for role in candidates:
            self._try_assume_role(role, findings, api_calls)

        if not findings:
            return self._make_result(TTPresultStatus.FAILED, self._target, raw_api_calls=api_calls,
                error="No candidate roles found.")

        status = TTPresultStatus.PARTIAL if any(f.get("type") == "permission_denied" for f in findings) else TTPresultStatus.SUCCESS
        return self._make_result(status, self._target, findings, api_calls)

    def _find_candidate_roles(self, findings, api_calls):
        api_calls.append("iam:ListRoles")
        candidates = []
        try:
            for page in self._iam.get_paginator("list_roles").paginate():
                for role in page["Roles"]:
                    if self._is_candidate(role):
                        candidates.append(role)
                        findings.append({
                            "type": "candidate_role_found",
                            "role_name": role["RoleName"],
                            "role_arn": role["Arn"],
                            "severity": "MEDIUM",
                        })
                        self._log_finding("candidate_role_found", role["RoleName"])
        except ClientError as e:
            self._handle_error("iam:ListRoles", e, findings)
        return candidates

    def _is_candidate(self, role):
        """Check if the role's trust policy could allow the target user to assume it."""
        account_id = config.AWS_ACCOUNT_ID
        for stmt in role.get("AssumeRolePolicyDocument", {}).get("Statement", []):
            if stmt.get("Effect") != "Allow":
                continue
            principal = stmt.get("Principal", {})
            if principal == "*":
                return True
            aws_p = principal.get("AWS", "") if isinstance(principal, dict) else ""
            for p in ([aws_p] if isinstance(aws_p, str) else aws_p):
                if p == f"arn:aws:iam::{account_id}:root" or self._target in p:
                    return True
        return False

    def _try_assume_role(self, role, findings, api_calls):
        api_calls.append("sts:AssumeRole")
        try:
            self._sts.assume_role(
                RoleArn=role["Arn"],
                RoleSessionName=f"cloudsweeper-sim-{self._target}",
                DurationSeconds=900,
            )
            findings.append({
                "type": "role_assumption_successful",
                "role_name": role["RoleName"],
                "assumed_by": self._target,
                "severity": "CRITICAL",
            })
            self._log_finding("role_assumption_successful", f"{self._target} -> {role['RoleName']}")
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDenied", "AccessDeniedException"):
                findings.append({"type": "role_assumption_denied", "role_name": role["RoleName"]})
                self._log_finding("role_assumption_denied", role["RoleName"])
            else:
                self._handle_error("sts:AssumeRole", e, findings)

    def _handle_error(self, api_call, error, findings):
        code = error.response["Error"]["Code"]
        if code in ("AccessDenied", "AccessDeniedException"):
            findings.append({"type": "permission_denied", "api_call": api_call})
            self._logger.warning(f"Access denied on {api_call}", extra={"ttp_id": self.ttp_id})
        else:
            self._logger.error(f"Unexpected error on {api_call}: {error}", extra={"ttp_id": self.ttp_id})
