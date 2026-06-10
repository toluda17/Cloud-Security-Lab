"""
s3_enum.py - S3 bucket enumeration simulation.
MITRE ATT&CK: T1530 (Data from Cloud Storage)
Tactic: Collection

After IAM recon, S3 is usually the next thing an attacker checks.
Buckets are where the interesting stuff lives: backups, config files,
credentials that got committed by accident.

I list all buckets, check their access controls, try to list their
contents, and flag anything with a sensitive-sounding name.
All read-only, nothing destructive.
"""

from botocore.exceptions import ClientError
from cloudsweeper.attack.ttp_base import TTP, TTPresultStatus
from cloudsweeper.config import config
from cloudsweeper.utils.aws_client import AWSClientFactory

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
    def ttp_id(self): return "s3_enum"

    @property
    def mitre_id(self): return "T1530"

    @property
    def mitre_tactic(self): return "Collection"

    def describe(self):
        return (
            "Lists all S3 buckets, checks access controls and public access settings, "
            "tries to list objects, and flags sensitive-sounding bucket names. Shows up "
            "in CloudTrail as a burst of s3.amazonaws.com read events."
        )

    def execute(self):
        self._log_start(self._target)
        findings, api_calls = [], []

        buckets = self._list_buckets(findings, api_calls)
        if not buckets:
            return self._make_result(TTPresultStatus.PARTIAL, self._target,
                findings=findings, raw_api_calls=api_calls, error="No buckets found or ListBuckets was denied.")

        for bucket_name in buckets:
            self._check_public_access(bucket_name, findings, api_calls)
            self._list_objects(bucket_name, findings, api_calls)
            self._check_sensitive_name(bucket_name, findings)

        status = TTPresultStatus.PARTIAL if any(f.get("type") == "permission_denied" for f in findings) else TTPresultStatus.SUCCESS
        return self._make_result(status, self._target, findings, api_calls)

    def _list_buckets(self, findings, api_calls):
        api_calls.append("s3:ListBuckets")
        try:
            response = self._s3.list_buckets()
            for bucket in response.get("Buckets", []):
                findings.append({"type": "bucket_discovered", "bucket_name": bucket["Name"]})
                self._log_finding("bucket_discovered", bucket["Name"])
            return [b["Name"] for b in response.get("Buckets", [])]
        except ClientError as e:
            self._handle_error("s3:ListBuckets", e, findings)
            return []

    def _check_public_access(self, bucket_name, findings, api_calls):
        api_calls.append("s3:GetBucketPublicAccessBlock")
        try:
            resp = self._s3.get_public_access_block(Bucket=bucket_name)
            disabled = [k for k, v in resp.get("PublicAccessBlockConfiguration", {}).items() if not v]
            if disabled:
                findings.append({"type": "public_access_block_disabled", "bucket_name": bucket_name, "disabled_settings": disabled, "severity": "HIGH"})
                self._log_finding("public_access_block_disabled", bucket_name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                findings.append({"type": "no_public_access_block", "bucket_name": bucket_name, "severity": "MEDIUM"})
                self._log_finding("no_public_access_block", bucket_name)
            else:
                self._handle_error("s3:GetBucketPublicAccessBlock", e, findings)

    def _list_objects(self, bucket_name, findings, api_calls):
        api_calls.append("s3:ListObjectsV2")
        try:
            resp = self._s3.list_objects_v2(Bucket=bucket_name, MaxKeys=10)
            objects = resp.get("Contents", [])
            if objects:
                findings.append({
                    "type": "bucket_readable",
                    "bucket_name": bucket_name,
                    "object_count": resp.get("KeyCount", 0),
                    "sample_keys": [o["Key"] for o in objects[:5]],
                    "severity": "HIGH",
                })
                self._log_finding("bucket_readable", f"{bucket_name} ({len(objects)} objects)")
            else:
                findings.append({"type": "bucket_empty", "bucket_name": bucket_name})
        except ClientError as e:
            self._handle_error("s3:ListObjectsV2", e, findings)

    def _check_sensitive_name(self, bucket_name, findings):
        matched = [kw for kw in SENSITIVE_KEYWORDS if kw in bucket_name.lower()]
        if matched:
            findings.append({"type": "sensitive_bucket_name", "bucket_name": bucket_name, "matched_keywords": matched, "severity": "MEDIUM"})
            self._log_finding("sensitive_bucket_name", f"{bucket_name} ({matched})")

    def _handle_error(self, api_call, error, findings):
        code = error.response["Error"]["Code"]
        if code in ("AccessDenied", "AccessDeniedException"):
            findings.append({"type": "permission_denied", "api_call": api_call})
            self._logger.warning(f"Access denied on {api_call}", extra={"ttp_id": self.ttp_id})
        else:
            self._logger.error(f"Unexpected error on {api_call}: {error}", extra={"ttp_id": self.ttp_id})
