"""
aws_client.py — one place to get boto3 clients, so the rest of the
project doesn't have to think about sessions or retry logic.

Every module in CloudSweeper gets its AWS clients from here. That way
if I ever need to swap credentials or change the retry behaviour, I do
it once and it applies everywhere.

Usage:
    from cloudsweeper.utils.aws_client import AWSClientFactory
    iam = AWSClientFactory.get_client("iam")
    s3  = AWSClientFactory.get_client("s3")
"""

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from typing import Optional

from cloudsweeper.config import config
from cloudsweeper.utils.logger import get_logger

logger = get_logger(__name__)

# Adaptive retry means boto3 backs off automatically when it hits throttling.
# This matters during simulation runs that fire a lot of API calls at once.
_BOTO_CONFIG = Config(
    region_name=config.AWS_REGION,
    retries={"max_attempts": 3, "mode": "adaptive"},
)


class AWSClientFactory:
    """
    Builds and caches boto3 clients. I cache by (service, region) so I'm
    not opening a new connection for every API call — that adds up fast
    when the simulation engine is running multiple TTPs in sequence.
    """

    _session: Optional[boto3.Session] = None
    _client_cache: dict = {}

    @classmethod
    def _get_session(cls) -> boto3.Session:
        # Lazy — only create the session the first time something asks for a client.
        if cls._session is None:
            logger.debug(
                "Starting boto3 session",
                extra={"profile": config.AWS_PROFILE, "region": config.AWS_REGION},
            )
            cls._session = boto3.Session(
                profile_name=config.AWS_PROFILE if config.AWS_PROFILE != "default" else None,
                region_name=config.AWS_REGION,
            )
        return cls._session

    @classmethod
    def get_client(cls, service: str, region: Optional[str] = None) -> boto3.client:
        """
        Get a boto3 client for any AWS service. Pass a region override if
        you need to talk to a service outside the default region (e.g. IAM
        is global, but sometimes you want an S3 client in us-east-1).

        Raises RuntimeError if credentials are missing or invalid — better
        to fail loudly at startup than silently mid-simulation.
        """
        effective_region = region or config.AWS_REGION
        cache_key = f"{service}:{effective_region}"

        if cache_key not in cls._client_cache:
            try:
                session = cls._get_session()
                client = session.client(
                    service,
                    region_name=effective_region,
                    config=_BOTO_CONFIG,
                )
                cls._client_cache[cache_key] = client
                logger.debug(f"Created {service} client ({effective_region})")
            except (BotoCoreError, ClientError) as e:
                raise RuntimeError(
                    f"Couldn't create a boto3 client for '{service}': {e}"
                ) from e

        return cls._client_cache[cache_key]

    @classmethod
    def get_resource(cls, service: str) -> boto3.resource:
        """
        Higher-level boto3 resource API — mainly useful for iterating S3
        objects without dealing with pagination manually.
        """
        session = cls._get_session()
        return session.resource(service, config=_BOTO_CONFIG)

    @classmethod
    def reset(cls) -> None:
        """Wipe the session and cache. Handy if credentials change mid-run."""
        cls._session = None
        cls._client_cache = {}
        logger.debug("AWS client cache cleared")


def get_caller_identity() -> dict:
    """
    Quick sanity check — calls STS to confirm who I'm running as before
    anything else happens. I call this at the top of every entry-point
    script so I know immediately if the credentials are wrong or expired.

    Returns a dict with UserId, Account, and Arn.
    """
    try:
        sts = AWSClientFactory.get_client("sts")
        identity = sts.get_caller_identity()
        logger.info(
            "Running as",
            extra={
                "account": identity["Account"],
                "arn": identity["Arn"],
            },
        )
        return identity
    except ClientError as e:
        raise RuntimeError(f"Couldn't confirm AWS identity — check your credentials: {e}") from e
