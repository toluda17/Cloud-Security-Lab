"""
recon_rules.py - detects IAM reconnaissance activity.

I'm looking for a spike of IAM read API calls from a single identity
in a short window. That pattern is what iam_recon.py generates, and
it's not something a normal user does in day-to-day work.
"""

from cloudsweeper.config import config


# The IAM read calls that iam_recon.py makes
RECON_API_CALLS = {
    "ListUsers", "ListRoles", "ListGroups",
    "ListAttachedGroupPolicies", "ListAttachedUserPolicies",
    "ListUserPolicies", "ListGroupsForUser", "GetRole",
}


def detect_iam_recon(events):
    """
    Flag any identity that makes more IAM read calls than the threshold
    within the event window. Returns a list of alert dicts.
    """
    # Count IAM read calls per identity
    call_counts = {}
    for event in events:
        if event.get("eventSource") != "iam.amazonaws.com":
            continue
        if event.get("eventName") not in RECON_API_CALLS:
            continue

        identity = _get_identity(event)
        call_counts[identity] = call_counts.get(identity, 0) + 1

    alerts = []
    for identity, count in call_counts.items():
        if count >= config.RECON_SPIKE_THRESHOLD:
            alerts.append({
                "rule": "iam_recon_spike",
                "mitre_id": "T1087.004",
                "mitre_tactic": "Discovery",
                "severity": "HIGH",
                "identity": identity,
                "api_call_count": count,
                "threshold": config.RECON_SPIKE_THRESHOLD,
                "detail": f"{identity} made {count} IAM read calls, threshold is {config.RECON_SPIKE_THRESHOLD}",
            })

    return alerts


def _get_identity(event):
    """Pull the identity string out of a CloudTrail event."""
    user_identity = event.get("userIdentity", {})
    return (
        user_identity.get("userName")
        or user_identity.get("arn")
        or user_identity.get("type", "unknown")
    )
