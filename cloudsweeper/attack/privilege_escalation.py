"""
privilege_escalation.py - Privilege escalation simulation.
MITRE ATT&CK: T1484.001 (Domain Policy Modification: PassRole abuse)
Tactic: Privilege Escalation

After recon, an attacker knows what roles exist. Now they try to
actually move to a more privileged identity using AssumeRole.

If a role's trust policy allows the current identity to assume it,
you call sts:AssumeRole and get temporary credentials for that role.
That's the escalation path I'm simulating here.

I check which roles look assumable based on their trust policies,
then actually try AssumeRole against them. If it works, I record it
as a critical finding and immediately discard the credentials.
Nothing destructive happens either way.
"""

from botocore.exceptions import ClientError

from cloudsweeper.attack.ttp_base import TTP, TTPresult, TTPresultStatus
from cloudsweeper.config import config
from cloudsweeper.utils.aws_client import AWSClientFactory


class PrivilegeEscalation(TTP):

    def __init__(self, run_id=None):
        super().__init__(run_id)
        self._iam = AWSClientFactory.get_client("iam")
        self._sts = AWSClientFactory.get_client("sts")
        self._target = config.SIM_TARGET_USER

    @property
    def ttp_id(self):
        return "privilege_escalation"

    @property
    def mitre_id(self):
        return "T1484.001"

    @property
    def mitre_tactic(self):
        return "Privilege Escalation"

    def describe(self):
        return (
            "Simulates privilege escalation via AssumeRole abuse. Checks which roles "
            "the target identity could assume based on their trust policies, then "
            "attempts sts:AssumeRole against each one. In CloudTrail these show up "
            "as sts:AssumeRole calls from a low-privilege identity, which is the "
            "pattern the priv-esc detection rule looks for."
        )

    def execute(self):
        self._log_start(self._target)

        findings = []
        api_calls = []

        # Find roles that look assumable based on their trust policies
        candidate_roles = self._find_candidate_roles(findings, api_calls)

        # Try to actually assume each one
        for role in candidate_roles:
            self._try_assume_role(role, findings, api_calls)

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

    def _find_candidate_roles(self, findings, api_calls):
        """
        List all roles and flag any whose trust policy might allow
        the target identity to assume them. I'm looking for:
        - Principal: * (anyone can assume it)
        - Principal includes the full account root (any user in the account)
        - Principal includes the target user's ARN directly
        """
        api_calls.append("iam:ListRoles")
        candidates = []

        try:
            paginator = self._iam.get_paginator("list_roles")
            for page in paginator.paginate():
                for role in page["Roles"]:
                    if self._is_candidate(role):
                        candidates.append(role)
                        findings.append({
                            "type": "candidate_role_found",
                            "role_name": role["RoleName"],
                            "role_arn": role["Arn"],
                            "severity": "MEDIUM",
                            "detail": f"{role['RoleName']} trust policy may allow assumption by {self._target}",
                        })
                        self._log_finding("candidate_role_found", role["RoleName"])
        except ClientError as e:
            self._handle_error("iam:ListRoles", e, findings)

        return candidates

    def _is_candidate(self, role):
        """Check if a role's trust policy could allow the target user to assume it."""
        trust = role.get("AssumeRolePolicyDocument", {})
        account_id = config.AWS_ACCOUNT_ID

        for statement in trust.get("Statement", []):
            if statement.get("Effect") != "Allow":
                continue

            principal = statement.get("Principal", {})

            # Wildcard principal, anyone can assume this
            if principal == "*":
                return True

            aws_principal = principal.get("AWS", "") if isinstance(principal, dict) else ""
            if isinstance(aws_principal, str):
                aws_principal = [aws_principal]

            for p in aws_principal:
                # Full account trust means any IAM user in the account could assume it
                if p == f"arn:aws:iam::{account_id}:root":
                    return True
                # Target user is trusted directly
                if self._target in p:
                    return True

        return False

    def _try_assume_role(self, role, findings, api_calls):
        """
        Actually attempt to assume the role. If it works, that confirms
        the escalation path is real. I discard the credentials immediately.
        If it's denied, I record the attempt anyway.
        """
        api_calls.append("sts:AssumeRole")
        role_arn = role["Arn"]
        role_name = role["RoleName"]

        try:
            self._sts.assume_role(
                RoleArn=role_arn,
                RoleSessionName=f"cloudsweeper-sim-{self._target}",
                DurationSeconds=900,
            )
            # If we get here, it worked. This is a critical finding.
            findings.append({
                "type": "role_assumption_successful",
                "role_name": role_name,
                "role_arn": role_arn,
                "assumed_by": self._target,
                "severity": "CRITICAL",
                "detail": f"{self._target} successfully assumed {role_name}",
            })
            self._log_finding("role_assumption_successful", f"{self._target} -> {role_name}")

        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDenied", "AccessDeniedException"):
                # Denied. Record the attempt anyway.
                findings.append({
                    "type": "role_assumption_denied",
                    "role_name": role_name,
                    "detail": f"AssumeRole denied for {role_name}",
                })
                self._log_finding("role_assumption_denied", role_name)
            else:
                self._handle_error("sts:AssumeRole", e, findings)

    def _handle_error(self, api_call, error, findings):
        """AccessDenied is a finding, not a crash."""
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
