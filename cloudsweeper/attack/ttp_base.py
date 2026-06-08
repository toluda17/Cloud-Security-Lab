"""
ttp_base.py — the base class every attack module inherits from.

I built this so that adding a new TTP later is just: create a file,
subclass TTP, fill in the three required properties and execute().
Nothing else in the framework needs to change. The runner, the
detection engine, and the report generator all work with TTPresult
objects and don't care which specific technique produced them.

MITRE ATT&CK reference: https://attack.mitre.org/

Quick example of how to build a new TTP:

    from cloudsweeper.attack.ttp_base import TTP, TTPresult, TTPresultStatus

    class MyTTP(TTP):
        @property
        def ttp_id(self) -> str:
            return "my_ttp"

        @property
        def mitre_id(self) -> str:
            return "T1234.001"

        @property
        def mitre_tactic(self) -> str:
            return "Discovery"

        def execute(self) -> TTPresult:
            # do stuff, return a result
            ...

        def describe(self) -> str:
            return "What this TTP does and why an attacker would use it."
"""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class TTPresultStatus(Enum):
    SUCCESS = "success"  # ran and got findings
    PARTIAL = "partial"  # some calls worked, some got permission-denied
    FAILED  = "failed"   # couldn't run at all
    SKIPPED = "skipped"  # dry_run or explicitly skipped


@dataclass
class TTPresult:
    """
    Everything a TTP knows about what it did and what it found.

    I return one of these from every execute() call rather than just
    printing to stdout — it means the runner and detection engine can
    actually work with the results programmatically.

    The raw_api_calls field is important: it's a list of every AWS API
    call the TTP made (e.g. "iam:ListUsers"). The detection engine uses
    this as ground truth when it's checking whether its rules would have
    caught the simulation.
    """

    status: TTPresultStatus
    ttp_id: str
    mitre_id: str
    mitre_tactic: str
    target: str
    findings: list[dict[str, Any]] = field(default_factory=list)
    raw_api_calls: list[str] = field(default_factory=list)
    error: str | None = None
    executed_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    run_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def to_dict(self) -> dict[str, Any]:
        """Flatten to a plain dict for JSON serialisation in reports."""
        return {
            "run_id":        self.run_id,
            "ttp_id":        self.ttp_id,
            "mitre_id":      self.mitre_id,
            "mitre_tactic":  self.mitre_tactic,
            "target":        self.target,
            "status":        self.status.value,
            "findings":      self.findings,
            "raw_api_calls": self.raw_api_calls,
            "error":         self.error,
            "executed_at":   self.executed_at,
        }

    @property
    def succeeded(self) -> bool:
        return self.status in (TTPresultStatus.SUCCESS, TTPresultStatus.PARTIAL)


class TTP(ABC):
    """
    Abstract base class for all attack simulation modules.

    I made the three identity properties (ttp_id, mitre_id, mitre_tactic)
    abstract on purpose — you can't instantiate a TTP without a MITRE
    technique ID. That way the MITRE mapping is enforced at the code level,
    not just in documentation.

    The _make_result() helper is there so subclasses don't have to repeat
    all the identity fields every time they want to return a result.
    """

    def __init__(self, run_id: str | None = None):
        """
        Pass a run_id if you want to group multiple TTPs from the same
        simulation run together in logs and reports. If you don't pass one,
        a new UUID gets generated automatically.
        """
        self.run_id = run_id or str(uuid.uuid4())
        # Importing here avoids a circular dependency at module load time
        from cloudsweeper.utils.logger import get_logger
        self._logger = get_logger(f"cloudsweeper.attack.{self.ttp_id}")

    # --- Identity — every subclass must define these ---

    @property
    @abstractmethod
    def ttp_id(self) -> str:
        """
        Short name for this technique. Used in logs and report keys.
        e.g. "iam_recon", "s3_enum", "privilege_escalation"
        """

    @property
    @abstractmethod
    def mitre_id(self) -> str:
        """
        MITRE ATT&CK technique ID. Include the sub-technique if there is one.
        e.g. "T1087.004", "T1530", "T1484.001"
        """

    @property
    @abstractmethod
    def mitre_tactic(self) -> str:
        """
        The MITRE tactic this technique falls under.
        e.g. "Discovery", "Collection", "Privilege Escalation"
        """

    # --- Behaviour — every subclass must implement these ---

    @abstractmethod
    def execute(self) -> TTPresult:
        """
        Run the simulation. This is where the actual AWS API calls happen.

        A few things I try to follow in every implementation:
        - Wrap boto3 calls in try/except. A permission denial is a finding
          (it shows where the IAM boundary is), not a reason to crash.
        - Log every API call in raw_api_calls as "service:ActionName"
          so the detection engine can match against CloudTrail events.
        - Never raise out of execute() — return a FAILED result instead.
          The runner needs to keep going even if one TTP doesn't work.
        """

    @abstractmethod
    def describe(self) -> str:
        """
        A plain-English description of what this TTP does, why an attacker
        would use it, and what it looks like in CloudTrail. I use these
        descriptions in ARCHITECTURE.md and when walking through the project
        in interviews.
        """

    # --- Shared helpers ---

    def _make_result(
        self,
        status: TTPresultStatus,
        target: str,
        findings: list[dict[str, Any]] | None = None,
        raw_api_calls: list[str] | None = None,
        error: str | None = None,
    ) -> TTPresult:
        """
        Build a TTPresult without repeating the identity fields every time.
        All subclasses should use this instead of constructing TTPresult
        directly.
        """
        return TTPresult(
            status=status,
            ttp_id=self.ttp_id,
            mitre_id=self.mitre_id,
            mitre_tactic=self.mitre_tactic,
            target=target,
            findings=findings or [],
            raw_api_calls=raw_api_calls or [],
            error=error,
            run_id=self.run_id,
        )

    def _log_start(self, target: str) -> None:
        """Log a consistent start message before a TTP runs."""
        self._logger.info(
            "Executing TTP",
            extra={
                "ttp_id":   self.ttp_id,
                "mitre_id": self.mitre_id,
                "tactic":   self.mitre_tactic,
                "target":   target,
                "run_id":   self.run_id,
            },
        )

    def _log_finding(self, finding_type: str, detail: str) -> None:
        """Log a single finding as it's discovered during execution."""
        self._logger.info(
            "Finding recorded",
            extra={"ttp_id": self.ttp_id, "type": finding_type, "detail": detail},
        )

    def __repr__(self) -> str:
        return f"<TTP id={self.ttp_id!r} mitre={self.mitre_id!r} run={self.run_id!r}>"
