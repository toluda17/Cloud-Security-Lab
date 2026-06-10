"""
credential_revoker.py - disables IAM access keys for a compromised user.

When a recon or priv-esc alert fires against a specific identity, this
is the first response action. I disable all active access keys for that
user so they can't make any more API calls.

DRY_RUN=true by default, which means it logs what it would do without
actually touching anything. I keep that on when demoing against my real
account for obvious reasons.
"""

from botocore.exceptions import ClientError
from cloudsweeper.config import config
from cloudsweeper.utils.aws_client import AWSClientFactory
from cloudsweeper.utils.logger import get_logger

logger = get_logger(__name__)


def revoke_credentials(username):
    """
    Disable all active access keys for the given IAM user.
    Returns a list of dicts describing what was done (or would be done).
    """
    iam = AWSClientFactory.get_client("iam")
    actions = []

    try:
        response = iam.list_access_keys(UserName=username)
        keys = response.get("AccessKeyMetadata", [])

        if not keys:
            logger.info(f"No access keys found for {username}")
            return actions

        for key in keys:
            if key["Status"] == "Active":
                action = {
                    "action": "disable_access_key",
                    "username": username,
                    "key_id": key["AccessKeyId"],
                    "dry_run": config.DRY_RUN,
                }

                if config.DRY_RUN:
                    logger.info(f"[DRY RUN] Would disable key {key['AccessKeyId']} for {username}")
                else:
                    iam.update_access_key(
                        UserName=username,
                        AccessKeyId=key["AccessKeyId"],
                        Status="Inactive",
                    )
                    logger.info(f"Disabled key {key['AccessKeyId']} for {username}")

                actions.append(action)

    except ClientError as e:
        logger.error(f"Failed to revoke credentials for {username}: {e}")

    return actions
