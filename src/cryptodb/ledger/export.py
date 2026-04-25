"""Ledger export to JSONL or WORM-compatible formats."""

import json
from datetime import datetime, timezone
from pathlib import Path

from cryptodb.ledger.chain import HashChain, LedgerEntry


def export_jsonl(entries: list[LedgerEntry], output_path: Path) -> None:
    """Append entries to a JSON Lines file."""
    with open(output_path, "a", encoding="utf-8") as f:
        for entry in entries:
            obj = {
                "entry_number": entry.entry_number,
                "timestamp": entry.timestamp.isoformat(),
                "actor_id": entry.actor_id,
                "action": entry.action,
                "resource_type": entry.resource_type,
                "resource_id": entry.resource_id,
                "result": entry.result,
                "details": entry.details,
                "client_ip": entry.client_ip,
                "session_id": entry.session_id,
                "previous_hash": entry.previous_hash,
                "entry_hash": entry.entry_hash,
            }
            f.write(json.dumps(obj, default=str) + "\n")


def export_checkpoint(chain: HashChain, output_path: Path) -> None:
    """Export a signed checkpoint of the current chain state."""
    checkpoint = {
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "ledger_length": chain.length,
        "last_hash": chain.last_hash,
        "hash_algorithm": "sha3_256",
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(checkpoint, f, indent=2)
