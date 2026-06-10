"""
data_access_rules.py - detects S3 enumeration activity.

I'm looking for a spike of S3 list calls from a single identity.
Normal users don't ListBuckets and ListObjects across multiple buckets
in quick succession. That's enumeration behaviour.
"""

from cloudsweeper.config import config


S3_ENUM_CALLS = {"ListBuckets", "ListObjectsV2", "ListObjects", "GetBucketAcl", "GetBucketPublicAccessBlock"}


def detect_s3_enumeration(events):
    """
    Flag any identity that makes more S3 list/access calls than the
    threshold within the event window. Returns a list of alert dicts.
    """
    call_counts = {}
    for event in events:
        if event.get("eventSource") != "s3.amazonaws.com":
            continue
        if event.get("eventName") not in S3_ENUM_CALLS:
            continue

        identity = _get_identity(event)
        call_counts[identity] = call_counts.get(identity, 0) + 1

    alerts = []
    for identity, count in call_counts.items():
        if count >= config.S3_ENUM_THRESHOLD:
            alerts.append({
                "rule": "s3_enumeration",
                "mitre_id": "T1530",
                "mitre_tactic": "Collection",
                "severity": "HIGH",
                "identity": identity,
                "api_call_count": count,
                "threshold": config.S3_ENUM_THRESHOLD,
                "detail": f"{identity} made {count} S3 enumeration calls, threshold is {config.S3_ENUM_THRESHOLD}",
            })

    return alerts


def _get_identity(event):
    user_identity = event.get("userIdentity", {})
    return (
        user_identity.get("userName")
        or user_identity.get("arn")
        or user_identity.get("type", "unknown")
    )
