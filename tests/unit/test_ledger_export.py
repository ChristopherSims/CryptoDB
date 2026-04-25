"""Unit tests for ledger export utilities."""

import tempfile
from pathlib import Path

from cryptodb.ledger.export import export_checkpoint, export_jsonl
from cryptodb.ledger.chain import HashChain


class TestExportCheckpoint:
    def test_export_basic(self) -> None:
        chain = HashChain()
        chain.append(
            actor_id="user-1",
            action="create",
            resource_type="record",
            resource_id="r1",
            details={"size": 100},
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir) / "checkpoint.json"
            export_checkpoint(chain, out)
            data = __import__("json").loads(out.read_text())
            assert data["ledger_length"] == 1
            assert data["last_hash"] == chain.last_hash
            assert "exported_at" in data

    def test_export_empty_chain(self) -> None:
        chain = HashChain()
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir) / "checkpoint.json"
            export_checkpoint(chain, out)
            data = __import__("json").loads(out.read_text())
            assert data["ledger_length"] == 0
            assert data["last_hash"] == chain.last_hash


class TestExportJsonl:
    def test_export_entries(self) -> None:
        chain = HashChain()
        chain.append(
            actor_id="user-1",
            action="create",
            resource_type="record",
            resource_id="r1",
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir) / "ledger.jsonl"
            export_jsonl(chain.get_entries(), out)
            lines = out.read_text().strip().split("\n")
            assert len(lines) == 1
            obj = __import__("json").loads(lines[0])
            assert obj["actor_id"] == "user-1"
