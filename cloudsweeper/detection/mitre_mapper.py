"""
mitre_mapper.py - maps alert rule names to MITRE ATT&CK details.

Each alert already has a mitre_id attached from the rule that fired it,
but this adds the full technique name and a link to the ATT&CK page so
the reports are actually useful to read rather than just showing an ID.
"""

# Full mapping of the techniques CloudSweeper covers
MITRE_MAP = {
    "T1087.004": {
        "technique": "Account Discovery: Cloud Account",
        "tactic": "Discovery",
        "url": "https://attack.mitre.org/techniques/T1087/004/",
        "description": "Adversaries enumerate cloud accounts to identify users, roles, and groups.",
    },
    "T1530": {
        "technique": "Data from Cloud Storage",
        "tactic": "Collection",
        "url": "https://attack.mitre.org/techniques/T1530/",
        "description": "Adversaries access data from cloud storage services like S3.",
    },
    "T1484.001": {
        "technique": "Domain Policy Modification: Group Policy Object",
        "tactic": "Privilege Escalation",
        "url": "https://attack.mitre.org/techniques/T1484/001/",
        "description": "Adversaries abuse IAM PassRole or AssumeRole to escalate privileges.",
    },
}


def enrich_alert(alert):
    """
    Add full MITRE technique details to an alert dict.
    Returns the alert with mitre_technique, mitre_url, and mitre_description added.
    If the technique ID isn't in the map, the alert comes back unchanged.
    """
    mitre_id = alert.get("mitre_id", "")
    details = MITRE_MAP.get(mitre_id)

    if details:
        alert["mitre_technique"] = details["technique"]
        alert["mitre_url"] = details["url"]
        alert["mitre_description"] = details["description"]

    return alert


def enrich_alerts(alerts):
    """Run enrich_alert on a list of alerts and return the updated list."""
    return [enrich_alert(alert) for alert in alerts]


def get_technique(mitre_id):
    """Look up a single technique ID. Returns None if not found."""
    return MITRE_MAP.get(mitre_id)
