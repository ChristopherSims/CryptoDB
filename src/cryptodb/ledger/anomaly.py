"""Anomaly detection on audit log patterns."""

from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass(frozen=True, slots=True)
class Anomaly:
    """A detected anomaly in the audit log."""

    rule: str
    description: str
    severity: str  # low, medium, high, critical
    actor_id: str | None
    timestamp: datetime
    details: dict | None = None


def detect_off_hours(
    entries: list[dict],
    workday_start: int = 7,
    workday_end: int = 19,
) -> list[Anomaly]:
    """Flag entries outside normal working hours."""
    anomalies: list[Anomaly] = []
    for entry in entries:
        ts = entry.get("timestamp")
        if isinstance(ts, str):
            ts = datetime.fromisoformat(ts)
        if ts and (ts.hour >= workday_end or ts.hour < workday_start):
            anomalies.append(
                Anomaly(
                    rule="off_hours",
                    description=f"Access at {ts.hour}:{ts.minute:02d} (outside {workday_start}-{workday_end})",
                    severity="low",
                    actor_id=entry.get("actor_id"),
                    timestamp=ts,
                )
            )
    return anomalies


def detect_bulk_access(entries: list[dict], threshold: int = 100) -> list[Anomaly]:
    """Flag actors with more than *threshold* accesses in the provided batch."""
    counts: dict[str | None, int] = {}
    for entry in entries:
        actor = entry.get("actor_id")
        counts[actor] = counts.get(actor, 0) + 1
    anomalies: list[Anomaly] = []
    for actor, count in counts.items():
        if count > threshold:
            anomalies.append(
                Anomaly(
                    rule="bulk_access",
                    description=f"Actor exceeded {threshold} accesses (actual: {count})",
                    severity="medium",
                    actor_id=actor,
                    timestamp=datetime.now(timezone.utc),
                    details={"excess": count - threshold},
                )
            )
    return anomalies
