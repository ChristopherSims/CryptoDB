"""Merkle tree / hash chain for tamper-evident audit logs."""

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Self

from cryptodb.config import settings


@dataclass(frozen=True, slots=True)
class LedgerEntry:
    """A single entry in the audit ledger."""

    entry_number: int
    timestamp: datetime
    actor_id: str | None
    action: str
    resource_type: str
    resource_id: str | None
    result: str
    details: dict | None
    client_ip: str | None
    session_id: str | None
    previous_hash: str
    entry_hash: str

    def canonical_bytes(self) -> bytes:
        """Deterministic serialization for hashing."""
        data = {
            "entry_number": self.entry_number,
            "timestamp": self.timestamp.isoformat(),
            "actor_id": self.actor_id,
            "action": self.action,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "result": self.result,
            "details": self.details,
            "client_ip": self.client_ip,
            "session_id": self.session_id,
            "previous_hash": self.previous_hash,
        }
        return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def compute_hash(self) -> str:
        """Compute the entry hash from canonical bytes."""
        h = hashlib.new(settings.ledger_hash_algorithm)
        h.update(self.canonical_bytes())
        return h.hexdigest()


class HashChain:
    """Maintains an in-memory hash chain for the audit ledger."""

    def __init__(self) -> None:
        self._entries: list[LedgerEntry] = []
        self._last_hash: str = self._genesis_hash()

    @staticmethod
    def _genesis_hash() -> str:
        """Return the hash of the genesis block."""
        return hashlib.new(settings.ledger_hash_algorithm, b"CRYPTODB_LEDGER_GENESIS").hexdigest()

    @staticmethod
    def _make_entry(
        entry_number: int,
        timestamp: datetime,
        actor_id: str | None,
        action: str,
        resource_type: str,
        resource_id: str | None,
        result: str,
        details: dict | None,
        client_ip: str | None,
        session_id: str | None,
        previous_hash: str,
        entry_hash: str,
    ) -> LedgerEntry:
        return LedgerEntry(
            entry_number=entry_number,
            timestamp=timestamp,
            actor_id=actor_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            result=result,
            details=details,
            client_ip=client_ip,
            session_id=session_id,
            previous_hash=previous_hash,
            entry_hash=entry_hash,
        )

    def append(
        self,
        actor_id: str | None,
        action: str,
        resource_type: str,
        resource_id: str | None,
        result: str = "success",
        details: dict | None = None,
        client_ip: str | None = None,
        session_id: str | None = None,
    ) -> LedgerEntry:
        """Append a new entry and return it."""
        entry_number = len(self._entries) + 1
        timestamp = datetime.now(timezone.utc)
        previous_hash = self._last_hash

        # Build the entry *without* the hash first
        entry = LedgerEntry(
            entry_number=entry_number,
            timestamp=timestamp,
            actor_id=actor_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            result=result,
            details=details,
            client_ip=client_ip,
            session_id=session_id,
            previous_hash=previous_hash,
            entry_hash="",  # placeholder
        )
        entry_hash = entry.compute_hash()
        # Replace with computed hash (dataclass is frozen, so rebuild)
        entry = LedgerEntry(
            entry_number=entry.entry_number,
            timestamp=entry.timestamp,
            actor_id=entry.actor_id,
            action=entry.action,
            resource_type=entry.resource_type,
            resource_id=entry.resource_id,
            result=entry.result,
            details=entry.details,
            client_ip=entry.client_ip,
            session_id=entry.session_id,
            previous_hash=entry.previous_hash,
            entry_hash=entry_hash,
        )
        self._entries.append(entry)
        self._last_hash = entry_hash
        return entry

    def verify(self) -> list[tuple[int, str]]:
        """Verify the chain. Returns list of (entry_number, error_msg) for failures."""
        failures: list[tuple[int, str]] = []
        expected_prev = self._genesis_hash()
        for entry in self._entries:
            if entry.previous_hash != expected_prev:
                failures.append(
                    (entry.entry_number, "previous_hash mismatch")
                )
            computed = entry.compute_hash()
            if computed != entry.entry_hash:
                failures.append(
                    (entry.entry_number, "entry_hash mismatch")
                )
            expected_prev = entry.entry_hash
        return failures

    @property
    def last_hash(self) -> str:
        return self._last_hash

    @property
    def length(self) -> int:
        return len(self._entries)

    def get_entries(self) -> list[LedgerEntry]:
        return list(self._entries)

    def create_checkpoint(self, checkpoint_number: int, signing_key: bytes) -> "LedgerCheckpoint":
        """Create a signed checkpoint of the current chain state."""
        import hmac
        import hashlib
        timestamp = datetime.now(timezone.utc)
        data = f"{checkpoint_number}||{self._last_hash}||{timestamp.isoformat()}"
        signature = hmac.new(signing_key, data.encode(), hashlib.sha3_256).hexdigest()
        return LedgerCheckpoint(
            checkpoint_number=checkpoint_number,
            last_entry_hash=self._last_hash,
            timestamp=timestamp,
            signature=signature,
        )


@dataclass(frozen=True, slots=True)
class LedgerCheckpoint:
    """A signed checkpoint of the ledger state."""

    checkpoint_number: int
    last_entry_hash: str
    timestamp: datetime
    signature: str

    def to_dict(self) -> dict:
        return {
            "checkpoint_number": self.checkpoint_number,
            "last_entry_hash": self.last_entry_hash,
            "timestamp": self.timestamp.isoformat(),
            "signature": self.signature,
        }
