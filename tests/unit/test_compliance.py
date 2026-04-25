"""Unit tests for compliance reports."""

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from cryptodb.compliance.reports import (
    ComplianceReport,
    gdpr_right_to_erasure_report,
    hipaa_access_report,
    soc2_evidence_export,
)
from cryptodb.engine import CryptoDBEngine


class TestComplianceReport:
    def test_dataclass_fields(self) -> None:
        report = ComplianceReport(
            standard="GDPR",
            generated_at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
            findings=[{"key": "value"}],
            summary={"count": 1},
        )
        assert report.standard == "GDPR"
        assert len(report.findings) == 1


class TestGdprReport:
    async def test_erasure_report(self, db_session: AsyncSession, admin_user, engine: CryptoDBEngine) -> None:
        record = await engine.put(db_session, admin_user, b"personal data")
        await db_session.commit()
        await engine.delete(db_session, admin_user, record.id)
        await db_session.commit()

        report = await gdpr_right_to_erasure_report(db_session, admin_user.id)
        assert report.standard == "GDPR-Art17"
        assert report.summary["deleted_records"] >= 1
        assert any(f["status"] == "DELETED" for f in report.findings)


class TestHipaaReport:
    async def test_access_report(self, db_session: AsyncSession, admin_user, engine: CryptoDBEngine) -> None:
        record = await engine.put(db_session, admin_user, b"phi data")
        await db_session.commit()
        await engine.get(db_session, admin_user, record.id)
        await db_session.commit()

        report = await hipaa_access_report(db_session, record.id)
        assert report.standard == "HIPAA-164.308"
        assert report.summary["access_events"] >= 1
        assert any(f["action"] == "read" for f in report.findings)


class TestSoc2Export:
    async def test_evidence_export(self, db_session: AsyncSession, admin_user, engine: CryptoDBEngine) -> None:
        record = await engine.put(db_session, admin_user, b"data")
        await db_session.commit()

        report = await soc2_evidence_export(db_session)
        assert report.standard == "SOC2-CC6.1"
        assert "total_audit_events" in report.summary
        assert "role_distribution" in report.summary
