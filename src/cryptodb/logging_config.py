"""Structured JSON logging configuration."""

import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any


class JSONFormatter(logging.Formatter):
    """Emit log records as single-line JSON."""

    def format(self, record: logging.LogRecord) -> str:
        log_obj: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if hasattr(record, "event"):
            log_obj["event"] = record.event
        if hasattr(record, "actor"):
            log_obj["actor"] = record.actor
        if hasattr(record, "record_id"):
            log_obj["record_id"] = record.record_id
        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_obj, default=str)


def setup_logging(level: int = logging.INFO) -> None:
    """Configure root logger for structured JSON output."""
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JSONFormatter())
    root = logging.getLogger()
    root.setLevel(level)
    root.handlers = [handler]
