"""
alert_generator.py - turns raw rule results into structured alerts.

The rule engine returns basic dicts. This module adds timestamps,
formats them consistently, sorts them by severity, and prints a
clean summary to the terminal.

Severity order: CRITICAL > HIGH > MEDIUM > LOW
"""

from datetime import datetime, timezone
from cloudsweeper.utils.logger import get_logger

logger = get_logger(__name__)

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def generate_alerts(raw_alerts):
    """
    Takes the list of raw alert dicts from the rule engine, adds a
    timestamp to each one, sorts them by severity, and returns them.
    """
    if not raw_alerts:
        return []

    alerts = []
    for raw in raw_alerts:
        alert = {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "rule":         raw.get("rule", "unknown"),
            "severity":     raw.get("severity", "MEDIUM"),
            "mitre_id":     raw.get("mitre_id", ""),
            "mitre_tactic": raw.get("mitre_tactic", ""),
            "identity":     raw.get("identity", "unknown"),
            "detail":       raw.get("detail", ""),
        }
        alerts.append(alert)

    # Sort by severity so the most critical stuff is always at the top
    alerts.sort(key=lambda a: SEVERITY_ORDER.get(a["severity"], 99))

    return alerts


def print_alerts(alerts):
    """Print a readable summary of all alerts to the terminal."""
    if not alerts:
        print("No alerts generated.")
        return

    print(f"\n--- {len(alerts)} alert(s) ---")
    for alert in alerts:
        print(f"\n[{alert['severity']}] {alert['rule']}")
        print(f"  MITRE:    {alert['mitre_id']} ({alert['mitre_tactic']})")
        print(f"  Identity: {alert['identity']}")
        print(f"  Detail:   {alert['detail']}")
        print(f"  Time:     {alert['timestamp']}")
