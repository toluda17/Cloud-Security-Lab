"""
config.py — where all the environment-specific stuff lives.

I load everything from a .env file so nothing sensitive is ever
hardcoded. The whole thing is a frozen dataclass, which just means
once it's built at startup, nothing can accidentally change it mid-run.

To use it anywhere in the project:
    from cloudsweeper.config import config
    print(config.AWS_REGION)
"""

import os
from dataclasses import dataclass, field
from dotenv import load_dotenv

load_dotenv()


@dataclass(frozen=True)
class CloudSweeperConfig:
    # --- AWS basics ---
    # Your 12-digit account ID. The only thing that'll break without it is
    # building CloudTrail S3 paths, but I validate for it at startup anyway.
    AWS_ACCOUNT_ID: str = field(default_factory=lambda: os.getenv("AWS_ACCOUNT_ID", ""))
    AWS_REGION: str = field(default_factory=lambda: os.getenv("AWS_REGION", "eu-west-2"))
    AWS_PROFILE: str = field(default_factory=lambda: os.getenv("AWS_PROFILE", "default"))

    # --- CloudTrail ---
    # This is the S3 bucket I set up in Lab Step 4. It already exists and
    # already has the right bucket policy — the detection engine reads from here.
    CLOUDTRAIL_BUCKET: str = field(
        default_factory=lambda: os.getenv(
            "CLOUDTRAIL_BUCKET", "my-cloudtrail-logs-406214277032"
        )
    )
    # CloudTrail writes logs under AWSLogs/<account_id>/CloudTrail/<region>/...
    CLOUDTRAIL_PREFIX: str = field(
        default_factory=lambda: os.getenv("CLOUDTRAIL_PREFIX", "AWSLogs")
    )
    # How far back the detection engine looks when it scans for suspicious activity.
    # 24 hours is enough to catch anything the simulation just generated.
    DETECTION_LOOKBACK_HOURS: int = field(
        default_factory=lambda: int(os.getenv("DETECTION_LOOKBACK_HOURS", "24"))
    )

    # --- Detection thresholds ---
    # These are the call-count limits that trigger each detection rule.
    # I've set them conservatively — a real attacker doing recon would blow
    # past 20 IAM calls easily, so this catches even slow enumeration.
    RECON_SPIKE_THRESHOLD: int = field(
        default_factory=lambda: int(os.getenv("RECON_SPIKE_THRESHOLD", "20"))
    )
    # 10 S3 list calls in a window is pretty clearly not normal user behaviour.
    S3_ENUM_THRESHOLD: int = field(
        default_factory=lambda: int(os.getenv("S3_ENUM_THRESHOLD", "10"))
    )
    # AssumeRole by itself is fine. Five of them in quick succession from the
    # same identity is worth flagging.
    PRIVESC_ASSUMEROLE_THRESHOLD: int = field(
        default_factory=lambda: int(os.getenv("PRIVESC_ASSUMEROLE_THRESHOLD", "5"))
    )

    # --- Simulation settings ---
    # DemoDev is the IAM user I created in Lab Step 2 — it's got limited
    # permissions, which makes it a realistic attacker starting point.
    SIM_TARGET_USER: str = field(
        default_factory=lambda: os.getenv("SIM_TARGET_USER", "DemoDev")
    )
    # DRY_RUN=true means the response layer logs what it *would* do but
    # doesn't actually touch anything. I keep this on by default because
    # I'm running this against a real AWS account and I'd rather not
    # accidentally revoke my own credentials.
    DRY_RUN: bool = field(
        default_factory=lambda: os.getenv("DRY_RUN", "true").lower() == "true"
    )

    # --- Output ---
    REPORT_OUTPUT_DIR: str = field(
        default_factory=lambda: os.getenv("REPORT_OUTPUT_DIR", "reports")
    )
    LOG_LEVEL: str = field(default_factory=lambda: os.getenv("LOG_LEVEL", "INFO"))

    def validate(self) -> None:
        """
        Call this at the top of any entry-point script. It'll catch missing
        config early with a clear error instead of a cryptic boto3 failure
        halfway through a simulation run.
        """
        missing = []
        if not self.AWS_ACCOUNT_ID:
            missing.append("AWS_ACCOUNT_ID")
        if missing:
            raise EnvironmentError(
                f"Missing required env vars: {', '.join(missing)}\n"
                f"Copy .env.example to .env and fill them in."
            )


# One instance, imported everywhere. No need to instantiate it yourself.
config = CloudSweeperConfig()
