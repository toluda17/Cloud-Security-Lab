"""
log_ingestor.py - fetches and parses CloudTrail logs from S3.

CloudTrail writes logs as gzipped JSON files to S3, organised by
account, region, and date. This module finds the right files,
downloads them, and returns a flat list of events the rule engine
can work with.

I also added a load_from_file() method so I can test the detection
rules offline using a local sample file without needing to hit S3.
"""

import gzip
import json
from datetime import datetime, timezone, timedelta

from botocore.exceptions import ClientError

from cloudsweeper.config import config
from cloudsweeper.utils.aws_client import AWSClientFactory
from cloudsweeper.utils.logger import get_logger

logger = get_logger(__name__)


class LogIngestor:

    def __init__(self):
        self._s3 = AWSClientFactory.get_client("s3")
        self._bucket = config.CLOUDTRAIL_BUCKET
        self._account_id = config.AWS_ACCOUNT_ID
        self._region = config.AWS_REGION

    def get_events(self, hours_back=None):
        """
        Fetch all CloudTrail events from the last N hours.
        Returns a flat list of events, one dict per API call recorded.
        """
        hours_back = hours_back or config.DETECTION_LOOKBACK_HOURS
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours_back)

        logger.info("Fetching CloudTrail logs", extra={"hours_back": hours_back})

        log_keys = self._list_log_files(cutoff)
        if not log_keys:
            logger.warning("No log files found for this time window")
            return []

        all_events = []
        for key in log_keys:
            events = self._parse_log_file(key)
            all_events.extend(events)

        logger.info(f"Loaded {len(all_events)} events from {len(log_keys)} files")
        return all_events

    def _list_log_files(self, cutoff):
        """
        List log files in the bucket that fall within our time window.
        CloudTrail path format:
        AWSLogs/<account_id>/CloudTrail/<region>/<year>/<month>/<day>/
        """
        keys = []
        now = datetime.now(timezone.utc)

        # Check today and yesterday to cover the full lookback window
        for date in [now, now - timedelta(days=1)]:
            prefix = (
                f"AWSLogs/{self._account_id}/CloudTrail/"
                f"{self._region}/{date.year}/{date.month:02d}/{date.day:02d}/"
            )
            try:
                paginator = self._s3.get_paginator("list_objects_v2")
                for page in paginator.paginate(Bucket=self._bucket, Prefix=prefix):
                    for obj in page.get("Contents", []):
                        if obj["LastModified"].replace(tzinfo=timezone.utc) >= cutoff:
                            keys.append(obj["Key"])
            except ClientError as e:
                logger.error(f"Failed to list files at {prefix}: {e}")

        return keys

    def _parse_log_file(self, key):
        """Download a log file from S3, decompress it, and return its events."""
        try:
            response = self._s3.get_object(Bucket=self._bucket, Key=key)
            raw = gzip.decompress(response["Body"].read())
            data = json.loads(raw)
            return data.get("Records", [])
        except ClientError as e:
            logger.error(f"Failed to download {key}: {e}")
            return []
        except Exception as e:
            logger.error(f"Failed to parse {key}: {e}")
            return []

    def load_from_file(self, filepath):
        """
        Load events from a local JSON file instead of S3.
        Used for testing detection rules offline with sample data.
        """
        try:
            with open(filepath) as f:
                data = json.load(f)
            events = data.get("Records", [])
            logger.info(f"Loaded {len(events)} events from {filepath}")
            return events
        except Exception as e:
            logger.error(f"Failed to load {filepath}: {e}")
            return []
