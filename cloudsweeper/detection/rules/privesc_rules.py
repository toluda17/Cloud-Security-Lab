"""
privesc_rules.py - detects privilege escalation via AssumeRole.

I'm looking for two things:
1. Multiple AssumeRole calls from a single identity in quick succession
2. Any AssumeRole call from an identity that looks like a regular IAM user
   rather than a service or role (those are the suspicious ones)
"""

from cloudsweeper.config import config


def detect_privilege_escalation(events):
    """
    Flag suspicious AssumeRole activity. Returns a list of alert dicts.
    """
    assume_role_calls = {}

    for event in events:
        if event.get("eventSource") != "sts.amazonaws.com":
            continue
        if event.get("eventName") != "AssumeRole":
            continue

        identity = _get_identity(event)
        if identity not in assume_role_calls:
            assume_role_calls[identity] = []
        assume_role_calls[identity].append(event)

    alerts = []
    for identity, calls in assume_role_calls.items():
        # Flag if they made more AssumeRole calls than the threshold
        if len(calls) >= config.PRIVESC_ASSUMEROLE_THRESHOLD:
            alerts.append({
                "rule": "assumerole_spike",
                "mitre_id": "T1484.001",
                "mitre_tactic": "Privilege Escalation",
                "severity": "HIGH",
                "identity": identity,
                "api_call_count": len(calls),
                "threshold": config.PRIVESC_ASSUMEROLE_THRESHOLD,
                "detail": f"{identity} called AssumeRole {len(calls)} times, threshold is {config.PRIVESC_ASSUMEROLE_THRESHOLD}",
            })

        # Also flag any AssumeRole from a regular IAM user specifically.
        # Services and roles assuming other roles is normal. A user doing
        # it is worth a closer look regardless of the count.
        if _is_iam_user(calls[0]):
            alerts.append({
                "rule": "iam_user_assumerole",
                "mitre_id": "T1484.001",
                "mitre_tactic": "Privilege Escalation",
                "severity": "MEDIUM",
                "identity": identity,
                "api_call_count": len(calls),
                "detail": f"IAM user {identity} called AssumeRole {len(calls)} time(s)",
            })

    return alerts


def _get_identity(event):
    user_identity = event.get("userIdentity", {})
    return (
        user_identity.get("userName")
        or user_identity.get("arn")
        or user_identity.get("type", "unknown")
    )


def _is_iam_user(event):
    """Return True if the event was made by a regular IAM user."""
    return event.get("userIdentity", {}).get("type") == "IAMUser"
