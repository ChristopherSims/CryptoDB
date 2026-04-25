"""Tests for Prometheus metrics module."""

from cryptodb.api.metrics import get_metrics_response, _HAS_PROMETHEUS


class TestGetMetricsResponse:
    def test_returns_bytes_and_content_type(self):
        data, ct = get_metrics_response()
        assert isinstance(data, bytes)
        assert isinstance(ct, str)
        if _HAS_PROMETHEUS:
            assert b"#" in data
            assert "prometheus" in ct
        else:
            assert b"not installed" in data
            assert ct == "text/plain"

    def test_dummy_metrics_noop(self):
        from cryptodb.api.metrics import records_created_total
        # Should not raise even if prometheus is not installed
        records_created_total.labels(cipher="aes").inc()
