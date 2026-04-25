"""Tests for ledger anomaly detection."""

from datetime import datetime, timezone

import pytest

from cryptodb.ledger.anomaly import Anomaly, detect_bulk_access, detect_off_hours


class TestDetectOffHours:
    def test_no_entries(self):
        assert detect_off_hours([]) == []

    def test_working_hours_no_anomaly(self):
        entries = [
            {"timestamp": datetime(2025, 4, 25, 12, 0, tzinfo=timezone.utc), "actor_id": "a1"},
        ]
        assert detect_off_hours(entries) == []

    def test_off_hours_detected(self):
        entries = [
            {"timestamp": datetime(2025, 4, 25, 5, 0, tzinfo=timezone.utc), "actor_id": "a1"},
        ]
        result = detect_off_hours(entries)
        assert len(result) == 1
        assert result[0].rule == "off_hours"
        assert result[0].severity == "low"

    def test_string_timestamp(self):
        entries = [
            {"timestamp": "2025-04-25T05:00:00+00:00", "actor_id": "a1"},
        ]
        result = detect_off_hours(entries)
        assert len(result) == 1

    def test_custom_workday(self):
        entries = [
            {"timestamp": datetime(2025, 4, 25, 6, 0, tzinfo=timezone.utc), "actor_id": "a1"},
        ]
        # 6:00 is outside 7-19, so should detect anomaly
        result = detect_off_hours(entries, workday_start=7, workday_end=19)
        assert len(result) == 1
        # 6:00 is outside 8-18, so should also detect anomaly
        result = detect_off_hours(entries, workday_start=8, workday_end=18)
        assert len(result) == 1

    def test_edge_exact_end_hour(self):
        entries = [
            {"timestamp": datetime(2025, 4, 25, 19, 0, tzinfo=timezone.utc), "actor_id": "a1"},
        ]
        result = detect_off_hours(entries)
        assert len(result) == 1

    def test_edge_exact_start_hour(self):
        entries = [
            {"timestamp": datetime(2025, 4, 25, 7, 0, tzinfo=timezone.utc), "actor_id": "a1"},
        ]
        assert detect_off_hours(entries) == []


class TestDetectBulkAccess:
    def test_no_entries(self):
        assert detect_bulk_access([]) == []

    def test_under_threshold(self):
        entries = [{"actor_id": "a1"} for _ in range(5)]
        assert detect_bulk_access(entries, threshold=10) == []

    def test_over_threshold(self):
        entries = [{"actor_id": "a1"} for _ in range(12)]
        result = detect_bulk_access(entries, threshold=10)
        assert len(result) == 1
        assert result[0].rule == "bulk_access"
        assert result[0].severity == "medium"
        assert result[0].actor_id == "a1"

    def test_multiple_actors(self):
        entries = [{"actor_id": "a1"} for _ in range(15)]
        entries += [{"actor_id": "a2"} for _ in range(5)]
        result = detect_bulk_access(entries, threshold=10)
        assert len(result) == 1
        assert result[0].actor_id == "a1"

    def test_none_actor(self):
        entries = [{"actor_id": None} for _ in range(15)]
        result = detect_bulk_access(entries, threshold=10)
        assert len(result) == 1
        assert result[0].actor_id is None

    def test_details_contains_excess(self):
        entries = [{"actor_id": "a1"} for _ in range(15)]
        result = detect_bulk_access(entries, threshold=10)
        assert result[0].details == {"excess": 5}


class TestAnomaly:
    def test_frozen_dataclass(self):
        a = Anomaly(rule="x", description="d", severity="high", actor_id="a", timestamp=datetime.now(timezone.utc))
        with pytest.raises(AttributeError):
            a.rule = "y"
