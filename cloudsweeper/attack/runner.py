"""
runner.py - runs all the attack modules in sequence.

I built this so I can kick off the full simulation in one go instead
of running each TTP manually. Everything shares the same run_id so
the results tie together in the logs.

Usage:
    python3 -m cloudsweeper.attack.runner
"""

import uuid
from datetime import datetime, timezone

from cloudsweeper.attack.iam_recon import IAMRecon
from cloudsweeper.attack.s3_enum import S3Enum
from cloudsweeper.attack.privilege_escalation import PrivilegeEscalation
from cloudsweeper.utils.logger import get_logger
from cloudsweeper.utils.aws_client import get_caller_identity
from cloudsweeper.config import config

logger = get_logger(__name__)


def run(run_id=None):
    """Run all TTPs in sequence and return the results."""
    run_id = run_id or str(uuid.uuid4())

    # Make sure we're running as the right identity before anything fires
    try:
        identity = get_caller_identity()
        print(f"Running as: {identity['Arn']}")
    except RuntimeError as e:
        print(f"Could not confirm AWS identity: {e}")
        return []

    ttps = [
        IAMRecon(run_id=run_id),
        S3Enum(run_id=run_id),
        PrivilegeEscalation(run_id=run_id),
    ]

    results = []
    for ttp in ttps:
        print(f"\nRunning {ttp.ttp_id} ({ttp.mitre_id})...")
        try:
            result = ttp.execute()
            results.append(result)
        except Exception as e:
            # If one TTP breaks unexpectedly, log it and keep going
            print(f"  {ttp.ttp_id} failed unexpectedly: {e}")

    _print_summary(results, run_id)
    return results


def _print_summary(results, run_id):
    """Print a summary of the full simulation run."""
    print("\n--- Simulation complete ---")
    print(f"run_id: {run_id}")

    total = 0
    for result in results:
        total += len(result.findings)
        print(f"\n{result.ttp_id} - {result.status.value}")
        for f in result.findings:
            label = (
                f.get("username")
                or f.get("bucket_name")
                or f.get("role_name")
                or f.get("detail", "")
            )
            severity = f" [{f['severity']}]" if "severity" in f else ""
            print(f"  - {f['type']}{severity}: {label}")

    print(f"\ntotal findings: {total}")


if __name__ == "__main__":
    config.validate()
    run()
