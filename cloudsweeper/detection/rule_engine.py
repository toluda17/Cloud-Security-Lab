"""
rule_engine.py - runs all detection rules against a list of events.

I import each rule function directly and run them all against the
same event list. Each rule returns a list of alerts, and I combine
them all into one flat list at the end.

Nothing clever here, it's just a loop that calls each rule and
collects the results.
"""

from cloudsweeper.detection.rules.recon_rules import detect_iam_recon
from cloudsweeper.detection.rules.data_access_rules import detect_s3_enumeration
from cloudsweeper.detection.rules.privesc_rules import detect_privilege_escalation
from cloudsweeper.utils.logger import get_logger

logger = get_logger(__name__)

# All detection rules in one place. To add a new rule, import it above
# and add it to this list.
RULES = [
    detect_iam_recon,
    detect_s3_enumeration,
    detect_privilege_escalation,
]


def run_rules(events):
    """
    Run all detection rules against the provided events.
    Returns a flat list of alert dicts.
    """
    if not events:
        logger.warning("No events to analyse")
        return []

    logger.info(f"Running {len(RULES)} rules against {len(events)} events")

    all_alerts = []
    for rule in RULES:
        try:
            alerts = rule(events)
            if alerts:
                logger.info(f"{rule.__name__} fired {len(alerts)} alert(s)")
            all_alerts.extend(alerts)
        except Exception as e:
            logger.error(f"{rule.__name__} threw an error: {e}")

    logger.info(f"Detection complete - {len(all_alerts)} total alerts")
    return all_alerts
