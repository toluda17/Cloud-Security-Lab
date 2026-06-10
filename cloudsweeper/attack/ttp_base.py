"""
ttp_base.py - base class for all attack modules.

Every TTP module inherits from this. It enforces a consistent structure
across all techniques so the runner and detection engine can treat them
the same way without caring about the details of each one.

To add a new TTP, just subclass TTP, fill in the three properties,
and implement execute() and describe(). Nothing else needs to change.
"""

from __future__ import annotations
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class TTPresultStatus(Enum):
    SUCCESS = "success"   # ran and got findings
    PARTIAL = "partial"   # some calls worked, some got denied
    FAILED  = "failed"    # couldn't run at all
    SKIPPED = "skipped"   # dry run or explicitly skipped


@dataclass
class TTPresult:
    """The result returned by every TTP's execute() method."""
    status: TTPresultStatus
    ttp_id: str
    mitre_id: str
    mitre_tactic: str
    target: str
    findings: list[dict[str, Any]] = field(default_factory=list)
    raw_api_calls: list[str] = field(default_factory=list)
    error: str | None = None
    executed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    run_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def to_dict(self):
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
    def succeeded(self):
        return self.status in (TTPresultStatus.SUCCESS, TTPresultStatus.PARTIAL)


class TTP(ABC):
    """
    Abstract base class for all TTP modules.

    Subclasses must define ttp_id, mitre_id, and mitre_tactic as properties,
    and implement execute() and describe().
    """

    def __init__(self, run_id=None):
        self.run_id = run_id or str(uuid.uuid4())
        from cloudsweeper.utils.logger import get_logger
        self._logger = get_logger(f"cloudsweeper.attack.{self.ttp_id}")

    @property
    @abstractmethod
    def ttp_id(self) -> str:
        """Short name for this technique e.g. 'iam_recon'"""

    @property
    @abstractmethod
    def mitre_id(self) -> str:
        """MITRE ATT&CK technique ID e.g. 'T1087.004'"""

    @property
    @abstractmethod
    def mitre_tactic(self) -> str:
        """MITRE tactic name e.g. 'Discovery'"""

    @abstractmethod
    def execute(self) -> TTPresult:
        """Run the simulation and return a TTPresult."""

    @abstractmethod
    def describe(self) -> str:
        """Plain English description of what this TTP does."""

    def _make_result(self, status, target, findings=None, raw_api_calls=None, error=None):
        """Build a TTPresult without repeating the identity fields every time."""
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

    def _log_start(self, target):
        self._logger.info(
            "Executing TTP",
            extra={"ttp_id": self.ttp_id, "mitre_id": self.mitre_id, "target": target, "run_id": self.run_id},
        )

    def _log_finding(self, finding_type, detail):
        self._logger.info("Finding recorded", extra={"ttp_id": self.ttp_id, "type": finding_type, "detail": detail})
