"""
s3_enum.py - S3 bucket enumeration simulation.
MITRE ATT&CK: T1530 (Data from Cloud Storage)
Tactic: Collection

After IAM recon, S3 is usually the next thing an attacker checks.
Buckets are where the interesting stuff lives: backups, config files,
credentials that got committed by accident. Even just knowing which
buckets exist and whether they're locked down is useful information.

I list all buckets, check their access controls, try to list their
contents, and flag anything with a name that sounds sensitive.
All read-only calls, nothing destructive.
"""

from botocore.exceptions import ClientError

from cloudsweeper.attack.ttp_base import TTP, TTPresult, TTPresultStatus
from cloudsweeper.config import config
from cloudsweeper.utils.aws_client import AWSClientFactory

# Names that suggest a bucket might have something worth looking at.
SENSITIVE_KEYWORDS = [
    "backup", "secret", "credential", "config", "key", "token",
    "password", "log", "audit", "finance", "prod", "database", "dump"
]


class S3Enum(TTP):

    def __init__(self, run_id=None):
        super().__init__(run_id)
        self._s3 = AWSClientFactory.get_client("s3")
        self._target = config.AWS_ACCOUNT_ID

    @property
    def ttp_id(self):
        return "s3_enum"

    @property
    def mitre_id(self):
        return "T1530"

    @property
    def mitre_tactic(self):
        return "Collection"

    def describe(self):
        return (
            "Simulates S3 bucket enumeration. Lists all buckets in the account, "
            "checks access controls and public access settings, tries to list objects, "
            "and flags buckets with sensitive-sounding names. In CloudTrail these "
            "show up as a burst of s3.amazonaws.com read events, which is what the "
            "S3 enumeration detection rule looks for."
        )

    def execute(self):
        self._log_start(self._target)

        findings = []
        api_calls = []

        # First, get the full list of buckets.
        buckets = self._list_buckets(findings, api_calls)

        if not buckets:
            return self._make_result(
                status=TTPresultStatus.PARTIAL,
                target=self._target,
                findings=findings,
                raw_api_calls=api_calls,
                error="No buckets found or ListBuckets was denied.",
            )

        # Then check each one.
        for bucket_name in buckets:
            self._check_public_access(bucket_name, findings, api_calls)
            self._list_objects(bucket_name, findings, api_calls)
            self._check_sensitive_name(bucket_name, findings)

        status = TTPresultStatus.SUCCESS
        if any(f.get("type") == "permission_denied" for f in findings):
            status = TTPresultStatus.PARTIAL

        return self._make_result(
            status=status,
            target=self._target,
            findings=findings,
            raw_api_calls=api_calls,
        )

    def _list_buckets(self, findings, api_calls):
        """Get every bucket in the account. One call, full picture."""
        api_calls.append("s3:ListBuckets")
        try:
            response = self._s3.list_buckets()
            buckets = response.get("Buckets", [])
            for bucket in buckets:
                findings.append({
                    "type": "bucket_discovered",
                    "bucket_name": bucket["Name"],
                    "created": bucket["CreationDate"].isoformat(),
                })
                self._log_finding("bucket_discovered", bucket["Name"])
            return [b["Name"] for b in buckets]
        except ClientError as e:
            self._handle_error("s3:ListBuckets", e, findings)
            return []

    def _check_public_access(self, bucket_name, findings, api_calls):
        """
        Check whether the bucket has public access blocked.
        If there's no block config at all, that's worth flagging too.
        """
        api_calls.append("s3:GetBucketPublicAccessBlock")
        try:
            response = self._s3.get_public_access_block(Bucket=bucket_name)
            block_config = response.get("PublicAccessBlockConfiguration", {})

            # All four of these should be True on a properly configured bucket.
            disabled = [k for k, v in block_config.items() if not v]
            if disabled:
                findings.append({
                    "type": "public_access_block_disabled",
                    "bucket_name": bucket_name,
                    "disabled_settings": disabled,
                    "severity": "HIGH",
                })
                self._log_finding("public_access_block_disabled", bucket_name)

        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                # No block config set at all. It relies entirely on bucket policy.
                findings.append({
                    "type": "no_public_access_block",
                    "bucket_name": bucket_name,
                    "severity": "MEDIUM",
                })
                self._log_finding("no_public_access_block", bucket_name)
            else:
                self._handle_error("s3:GetBucketPublicAccessBlock", e, findings)

    def _list_objects(self, bucket_name, findings, api_calls):
        """
        Try to list objects in the bucket. If this works, it confirms
        the identity has read access, not just knowledge that the bucket exists.
        I only pull the first 10 keys to keep it quick.
        """
        api_calls.append("s3:ListObjectsV2")
        try:
            response = self._s3.list_objects_v2(Bucket=bucket_name, MaxKeys=10)
            objects = response.get("Contents", [])

            if objects:
                findings.append({
                    "type": "bucket_readable",
                    "bucket_name": bucket_name,
                    "object_count": response.get("KeyCount", 0),
                    "sample_keys": [o["Key"] for o in objects[:5]],
                    "severity": "HIGH",
                })
                self._log_finding("bucket_readable", f"{bucket_name} ({len(objects)} objects)")
            else:
                findings.append({
                    "type": "bucket_empty",
                    "bucket_name": bucket_name,
                })

        except ClientError as e:
            self._handle_error("s3:ListObjectsV2", e, findings)

    def _check_sensitive_name(self, bucket_name, findings):
        """
        Flag buckets with names that suggest sensitive contents.
        No API call needed, just pattern matching on the name.
        An attacker would use this to decide which buckets to dig into first.
        """
        name_lower = bucket_name.lower()
        matched = [kw for kw in SENSITIVE_KEYWORDS if kw in name_lower]
        if matched:
            findings.append({
                "type": "sensitive_bucket_name",
                "bucket_name": bucket_name,
                "matched_keywords": matched,
                "severity": "MEDIUM",
            })
            self._log_finding("sensitive_bucket_name", f"{bucket_name} ({matched})")

    def _handle_error(self, api_call, error, findings):
        """
        AccessDenied is a finding, not a crash. It tells me exactly
        where the permission boundary is for this identity.
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
