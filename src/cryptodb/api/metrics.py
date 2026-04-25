"""Prometheus metrics collection.

Requires ``prometheus-client`` to be installed.
"""

try:
    from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST

    _HAS_PROMETHEUS = True

    records_created_total = Counter(
        "cryptodb_records_created_total", "Total records created", ["cipher"]
    )
    records_read_total = Counter(
        "cryptodb_records_read_total", "Total records read"
    )
    records_deleted_total = Counter(
        "cryptodb_records_deleted_total", "Total records deleted", ["secure"]
    )
    audit_entries_total = Counter(
        "cryptodb_audit_entries_total", "Total audit entries written", ["action"]
    )
    replication_errors_total = Counter(
        "cryptodb_replication_errors_total", "Total replication errors", ["node_id"]
    )
    auth_failures_total = Counter(
        "cryptodb_auth_failures_total", "Total authentication failures", ["reason"]
    )
    request_duration_seconds = Histogram(
        "cryptodb_request_duration_seconds", "Request duration", ["method", "endpoint"]
    )

except ImportError:
    _HAS_PROMETHEUS = False

    class _DummyMetric:
        def labels(self, *args, **kwargs):
            return self
        def inc(self, *args, **kwargs):
            pass
        def observe(self, *args, **kwargs):
            pass

    records_created_total = _DummyMetric()
    records_read_total = _DummyMetric()
    records_deleted_total = _DummyMetric()
    audit_entries_total = _DummyMetric()
    replication_errors_total = _DummyMetric()
    auth_failures_total = _DummyMetric()
    request_duration_seconds = _DummyMetric()


def get_metrics_response() -> tuple[bytes, str]:
    if _HAS_PROMETHEUS:
        return generate_latest(), CONTENT_TYPE_LATEST
    return b"# prometheus-client not installed\n", "text/plain"
