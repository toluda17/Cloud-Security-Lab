"""
report_generator.py - generates an incident report from alerts.

Once the detection engine has run and the response actions are done,
I write a report summarising everything: what was detected, which
identities were involved, the MITRE techniques, and what the response
layer did about it.

Reports are written to the reports/ directory in both JSON (for
machine readability) and Markdown (for humans).
"""

import json
import os
from datetime import datetime, timezone
from cloudsweeper.config import config
from cloudsweeper.utils.logger import get_logger

logger = get_logger(__name__)


def generate_report(alerts, response_actions=None):
    """
    Build and write an incident report.

    Args:
        alerts:           list of enriched alert dicts from the detection engine
        response_actions: list of action dicts from the response layer (optional)

    Returns the report dict.
    """
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    filename_ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    report = {
        "generated_at": timestamp,
        "total_alerts": len(alerts),
        "alerts": alerts,
        "response_actions": response_actions or [],
    }

    os.makedirs(config.REPORT_OUTPUT_DIR, exist_ok=True)

    # Write JSON report
    json_path = os.path.join(config.REPORT_OUTPUT_DIR, f"incident_{filename_ts}.json")
    with open(json_path, "w") as f:
        json.dump(report, f, indent=2)
    logger.info(f"JSON report written to {json_path}")

    # Write Markdown report
    md_path = os.path.join(config.REPORT_OUTPUT_DIR, f"incident_{filename_ts}.md")
    with open(md_path, "w") as f:
        f.write(_build_markdown(report))
    logger.info(f"Markdown report written to {md_path}")

    print(f"\nReports written to {config.REPORT_OUTPUT_DIR}/")
    print(f"  {os.path.basename(json_path)}")
    print(f"  {os.path.basename(md_path)}")

    return report


def _build_markdown(report):
    """Build the Markdown version of the report."""
    lines = [
        "# CloudSweeper Incident Report",
        f"\n**Generated:** {report['generated_at']}",
        f"**Total alerts:** {report['total_alerts']}",
        "\n---\n",
        "## Alerts",
    ]

    for alert in report["alerts"]:
        lines.append(f"\n### [{alert['severity']}] {alert['rule']}")
        lines.append(f"- **MITRE:** {alert.get('mitre_id')} - {alert.get('mitre_technique', '')}")
        lines.append(f"- **Tactic:** {alert.get('mitre_tactic', '')}")
        lines.append(f"- **Identity:** {alert.get('identity', '')}")
        lines.append(f"- **Detail:** {alert.get('detail', '')}")
        if alert.get("mitre_url"):
            lines.append(f"- **Reference:** {alert['mitre_url']}")

    if report["response_actions"]:
        lines.append("\n---\n")
        lines.append("## Response actions")
        for action in report["response_actions"]:
            dry = " (dry run)" if action.get("dry_run") else ""
            lines.append(f"- {action['action']} on {action.get('username', '')}{dry}")

    return "\n".join(lines)
