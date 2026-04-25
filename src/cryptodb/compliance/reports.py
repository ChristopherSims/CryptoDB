"""Compliance report generators for GDPR, HIPAA, and SOC2 evidence."""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cryptodb.db.metadata import AuditLog, Record, User


@dataclass(frozen=True, slots=True)
class ComplianceReport:
    """A generated compliance report."""

    standard: str
    generated_at: datetime
    findings: list[dict[str, Any]]
    summary: dict[str, Any]


async def gdpr_right_to_erasure_report(
    session: AsyncSession, user_id: str
) -> ComplianceReport:
    """Generate evidence that a user's data has been erased."""
    result = await session.execute(
        select(Record).where(Record.owner_id == user_id)
    )
    records = result.scalars().all()
    deleted = [r for r in records if r.is_deleted]
    active = [r for r in records if not r.is_deleted]

    findings = []
    for r in active:
        findings.append({
            "record_id": r.id,
            "status": "ACTIVE",
            "risk": "Personal data still present",
        })
    for r in deleted:
        findings.append({
            "record_id": r.id,
            "status": "DELETED",
            "blob_path": r.blob_path,
        })

    return ComplianceReport(
        standard="GDPR-Art17",
        generated_at=datetime.now(timezone.utc),
        findings=findings,
        summary={
            "total_records": len(records),
            "deleted_records": len(deleted),
            "active_records": len(active),
            "compliant": len(active) == 0,
        },
    )


async def hipaa_access_report(
    session: AsyncSession,
    record_id: str,
    start: datetime | None = None,
    end: datetime | None = None,
) -> ComplianceReport:
    """Generate an access report for a specific record (HIPAA 164.308)."""
    stmt = select(AuditLog).where(
        AuditLog.resource_type == "record",
        AuditLog.resource_id == record_id,
    )
    if start:
        stmt = stmt.where(AuditLog.timestamp >= start)
    if end:
        stmt = stmt.where(AuditLog.timestamp <= end)
    stmt = stmt.order_by(AuditLog.timestamp)

    result = await session.execute(stmt)
    entries = result.scalars().all()

    findings = []
    for entry in entries:
        findings.append({
            "timestamp": entry.timestamp.isoformat(),
            "actor_id": entry.actor_id,
            "action": entry.action,
            "result": entry.result,
            "client_ip": entry.client_ip,
        })

    return ComplianceReport(
        standard="HIPAA-164.308",
        generated_at=datetime.now(timezone.utc),
        findings=findings,
        summary={
            "record_id": record_id,
            "access_events": len(entries),
            "unique_actors": len({e.actor_id for e in entries}),
            "failed_accesses": len([e for e in entries if e.result != "success"]),
        },
    )


async def soc2_evidence_export(
    session: AsyncSession,
) -> ComplianceReport:
    """Export SOC2 Type II evidence: key management and access control."""
    # Key rotation events
    result = await session.execute(
        select(AuditLog).where(
            AuditLog.action.in_(["create", "delete", "read"]),
        ).order_by(AuditLog.timestamp)
    )
    entries = result.scalars().all()

    findings = []
    for entry in entries:
        findings.append({
            "timestamp": entry.timestamp.isoformat(),
            "actor_id": entry.actor_id,
            "action": entry.action,
            "resource_id": entry.resource_id,
            "result": entry.result,
        })

    # Count users by role
    user_result = await session.execute(select(User))
    users = user_result.scalars().all()
    role_counts: dict[str, int] = {}
    for u in users:
        role_counts[u.role] = role_counts.get(u.role, 0) + 1

    return ComplianceReport(
        standard="SOC2-CC6.1",
        generated_at=datetime.now(timezone.utc),
        findings=findings,
        summary={
            "total_audit_events": len(entries),
            "total_users": len(users),
            "role_distribution": role_counts,
        },
    )
