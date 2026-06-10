"""
run_full_pipeline.py - end-to-end demo script.

This runs the full CloudSweeper pipeline in one go:
1. Simulate attacks against the live AWS account
2. Fetch the CloudTrail logs those attacks generated
3. Run the detection rules against those logs
4. Generate alerts and enrich them with MITRE ATT&CK details
5. Dispatch the response actions and write the incident report

Run this from the repo root:
    python3 scripts/run_full_pipeline.py
"""

import sys
import os

# Make sure the repo root is on the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cloudsweeper.config import config
from cloudsweeper.attack.runner import run as run_simulation
from cloudsweeper.detection.log_ingestor import LogIngestor
from cloudsweeper.detection.rule_engine import run_rules
from cloudsweeper.detection.alert_generator import generate_alerts, print_alerts
from cloudsweeper.detection.mitre_mapper import enrich_alerts
from cloudsweeper.response.response_dispatcher import dispatch
from cloudsweeper.utils.logger import get_logger

logger = get_logger(__name__)


def main():
    config.validate()

    print("\n=== CloudSweeper - Full Pipeline ===\n")

    # Step 1: run the attack simulation
    print("--- Step 1: Attack Simulation ---")
    sim_results = run_simulation()
    total_findings = sum(len(r.findings) for r in sim_results)
    print(f"\nSimulation done. {total_findings} findings across {len(sim_results)} TTPs.")

    # Step 2: fetch CloudTrail logs
    # The simulation just made real AWS API calls, so the logs should be
    # in S3 within a few minutes. We look back 24 hours to catch them.
    print("\n--- Step 2: Fetching CloudTrail Logs ---")
    ingestor = LogIngestor()
    events = ingestor.get_events()
    print(f"Loaded {len(events)} CloudTrail events.")

    if not events:
        print("\nNo events found. CloudTrail logs may not have arrived yet.")
        print("Try again in a few minutes, or use sample data:")
        print("  Edit this script to use ingestor.load_from_file('sample_data/cloudtrail_sample.json')")
        sys.exit(0)

    # Step 3: run detection rules
    print("\n--- Step 3: Running Detection Rules ---")
    raw_alerts = run_rules(events)
    print(f"Rules fired {len(raw_alerts)} alert(s).")

    # Step 4: generate and enrich alerts
    print("\n--- Step 4: Generating Alerts ---")
    alerts = generate_alerts(raw_alerts)
    alerts = enrich_alerts(alerts)
    print_alerts(alerts)

    # Step 5: dispatch response and write report
    print("\n--- Step 5: Response and Reporting ---")
    report = dispatch(alerts)

    print("\n=== Pipeline complete ===")


if __name__ == "__main__":
    main()
