"""
response_dispatcher.py - routes alerts to the right response actions.

This is the entry point for the response layer. It takes the list of
alerts from the detection engine, decides what to do about each one,
and calls the right handler.

Right now it only handles credential revocation. The report is always
generated regardless of what other actions run.
"""

from cloudsweeper.response.credential_revoker import revoke_credentials
from cloudsweeper.response.report_generator import generate_report
from cloudsweeper.utils.logger import get_logger

logger = get_logger(__name__)

# Severity levels that trigger active response (not just reporting)
RESPONSE_SEVERITIES = {"CRITICAL", "HIGH"}


def dispatch(alerts):
    """
    Route each alert to the appropriate response handler.
    Always generates a report at the end.

    Returns the generated report dict.
    """
    if not alerts:
        logger.info("No alerts to respond to")
        return {}

    logger.info(f"Dispatching response for {len(alerts)} alert(s)")

    all_actions = []
    seen_identities = set()

    for alert in alerts:
        severity = alert.get("severity", "")
        identity = alert.get("identity", "")

        # Only respond to HIGH and CRITICAL alerts
        if severity not in RESPONSE_SEVERITIES:
            continue

        # Only revoke credentials once per identity even if multiple alerts fired
        if identity and identity not in seen_identities:
            seen_identities.add(identity)
            actions = revoke_credentials(identity)
            all_actions.extend(actions)

    return generate_report(alerts, all_actions)
