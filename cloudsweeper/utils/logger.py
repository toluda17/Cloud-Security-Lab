"""
logger.py — structured logging for the whole framework.

I wanted logs that are actually useful, not just noise. So there are
two modes: in production (LOG_LEVEL=INFO) everything comes out as
JSON so it's easy to parse or pipe into a SIEM. In development
(LOG_LEVEL=DEBUG) it switches to colour-coded human-readable output
because staring at JSON while debugging is miserable.

Usage:
    from cloudsweeper.utils.logger import get_logger
    logger = get_logger(__name__)
    logger.info("Starting recon", extra={"target": "DemoDev", "mitre": "T1087.004"})
"""

import logging
import json
import sys
from datetime import datetime, timezone
from typing import Any


# Fields that are part of every LogRecord internally — I filter these out
# so they don't clutter the JSON output alongside my custom extra fields.
_INTERNAL_FIELDS = frozenset({
    "name", "msg", "args", "levelname", "levelno", "pathname",
    "filename", "module", "exc_info", "exc_text", "stack_info",
    "lineno", "funcName", "created", "msecs", "relativeCreated",
    "thread", "threadName", "processName", "process", "message", "taskName",
})


class StructuredFormatter(logging.Formatter):
    """
    Outputs each log line as a single JSON object. The idea is that if
    I ever point this at a real SIEM or log aggregator, it can parse the
    output without any extra config.

    Example:
        {"ts": "2024-01-15T10:30:00Z", "level": "INFO",
         "module": "iam_recon", "msg": "Listed 4 IAM users", "ttp": "T1087.004"}
    """

    def format(self, record: logging.LogRecord) -> str:
        log_obj: dict[str, Any] = {
            "ts":     datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "level":  record.levelname,
            "module": record.name,
            "msg":    record.getMessage(),
        }
        # Pull in any extra fields passed via logger.info("msg", extra={...})
        for key, value in record.__dict__.items():
            if key not in _INTERNAL_FIELDS:
                log_obj[key] = value

        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_obj)


class HumanFormatter(logging.Formatter):
    """
    Colour-coded output for development. Makes it much easier to spot
    errors and warnings when you're watching a simulation run scroll by.
    """

    COLOURS = {
        "DEBUG":    "\033[36m",  # cyan
        "INFO":     "\033[32m",  # green
        "WARNING":  "\033[33m",  # yellow
        "ERROR":    "\033[31m",  # red
        "CRITICAL": "\033[35m",  # magenta
    }
    RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        colour = self.COLOURS.get(record.levelname, "")
        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        line = f"{colour}[{record.levelname}]{self.RESET} {ts} {record.name}: {record.getMessage()}"

        extras = {k: v for k, v in record.__dict__.items() if k not in _INTERNAL_FIELDS}
        if extras:
            line += "  " + "  ".join(f"{k}={v}" for k, v in extras.items())

        if record.exc_info:
            line += "\n" + self.formatException(record.exc_info)

        return line


_loggers: dict[str, logging.Logger] = {}


def get_logger(name: str, level: str | None = None) -> logging.Logger:
    """
    Get a named logger. Pass __name__ from the calling module and it'll
    show up correctly in the output. Loggers are cached so I'm not
    creating duplicates every time a module is imported.

    Set level to "DEBUG" to get the human-readable colour output instead
    of JSON — useful when you're actively working on a module.
    """
    if name in _loggers:
        return _loggers[name]

    from cloudsweeper.config import config  # local import avoids circular dep

    effective_level = level or config.LOG_LEVEL
    log_level = getattr(logging, effective_level.upper(), logging.INFO)

    logger = logging.getLogger(name)
    logger.setLevel(log_level)
    logger.propagate = False  # don't bubble up to the root logger

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(log_level)
        if effective_level.upper() == "DEBUG":
            handler.setFormatter(HumanFormatter())
        else:
            handler.setFormatter(StructuredFormatter())
        logger.addHandler(handler)

    _loggers[name] = logger
    return logger


class SimulationLogger:
    """
    A thin wrapper I use specifically during simulation runs to keep a
    structured record of what each TTP did. Every start, result, and
    error gets logged with the run_id so I can trace a full simulation
    run from a single ID — useful when the detection engine is trying
    to correlate what it found against what was actually simulated.
    """

    def __init__(self, run_id: str):
        self._logger = get_logger("cloudsweeper.simulation")
        self.run_id = run_id

    def log_ttp_start(self, ttp_id: str, mitre_id: str, target: str) -> None:
        self._logger.info(
            "TTP started",
            extra={"run_id": self.run_id, "ttp": ttp_id, "mitre": mitre_id, "target": target},
        )

    def log_ttp_result(self, ttp_id: str, success: bool, finding: str) -> None:
        level = logging.INFO if success else logging.WARNING
        self._logger.log(
            level,
            "TTP completed",
            extra={"run_id": self.run_id, "ttp": ttp_id, "success": success, "finding": finding},
        )

    def log_ttp_error(self, ttp_id: str, error: str) -> None:
        self._logger.error(
            "TTP failed",
            extra={"run_id": self.run_id, "ttp": ttp_id, "error": error},
        )
