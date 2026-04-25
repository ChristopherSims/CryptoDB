"""Record versioning: keep historical versions of records."""

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True, slots=True)
class VersionInfo:
    """Metadata about a record version."""

    version: int
    record_id: str
    previous_version_id: str | None
    created_at: datetime
    size_bytes: int


def bump_version(current_version: int) -> int:
    """Return the next version number."""
    return current_version + 1
