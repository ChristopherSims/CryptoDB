"""Replication engine: push encrypted backups to standby nodes."""

import hashlib
import logging
import secrets
from datetime import datetime, timezone

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cryptodb.auth.rbac import has_permission
from cryptodb.config import settings
from cryptodb.crypto.integrity import compute_hmac
from cryptodb.db.metadata import AuditLog, Record, ReplicationLog, ReplicationNode, User
from cryptodb.storage.blob import BlobStore

logger = logging.getLogger(__name__)

DEFAULT_HEADERS = {"Content-Type": "application/json", "Accept": "application/json"}
REPL_TIMEOUT = httpx.Timeout(30.0, connect=10.0)


def _checksum(data: bytes) -> str:
    return hashlib.sha3_256(data).hexdigest()


class ReplicationEngine:
    """Handles async push replication to registered standby nodes."""

    def __init__(self, blob_store: BlobStore | None = None) -> None:
        self._blob = blob_store or BlobStore()

    async def register_node(
        self,
        session: AsyncSession,
        user: User,
        name: str,
        endpoint_url: str,
    ) -> tuple[ReplicationNode, str]:
        """Register a new standby node; return the node and plaintext auth token."""
        if not has_permission(user, "admin"):
            raise PermissionError("Admin required")

        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha3_256(token.encode()).hexdigest()
        node = ReplicationNode(
            name=name,
            endpoint_url=endpoint_url.rstrip("/"),
            auth_token_hash=token_hash,
            created_by=user.id,
        )
        session.add(node)
        await session.flush()
        logger.info("Standby node registered", extra={"node_id": node.id, "name": name, "endpoint": endpoint_url})
        return node, token

    async def unregister_node(
        self,
        session: AsyncSession,
        user: User,
        node_id: str,
    ) -> None:
        """Remove a standby node and mark its pending replications as failed."""
        if not has_permission(user, "admin"):
            raise PermissionError("Admin required")

        result = await session.execute(select(ReplicationNode).where(ReplicationNode.id == node_id))
        node = result.scalar_one_or_none()
        if node is None:
            raise ValueError("Node not found")

        await session.execute(
            select(ReplicationLog)
            .where(ReplicationLog.node_id == node_id, ReplicationLog.status.in_(["pending", "sent"]))
        )
        # Bulk update not available easily in async ORM without sync call; do per-row later or use Core
        from sqlalchemy import update
        await session.execute(
            update(ReplicationLog)
            .where(ReplicationLog.node_id == node_id, ReplicationLog.status.in_(["pending", "sent"]))
            .values(status="failed", error_message="Node unregistered")
        )
        await session.delete(node)
        logger.info("Standby node unregistered", extra={"node_id": node_id})

    async def list_nodes(self, session: AsyncSession, user: User) -> list[ReplicationNode]:
        if not has_permission(user, "admin"):
            raise PermissionError("Admin required")
        result = await session.execute(select(ReplicationNode).order_by(ReplicationNode.created_at))
        return result.scalars().all()

    async def health_check_nodes(self, session: AsyncSession) -> list[tuple[str, bool, str | None]]:
        """Ping all active nodes and update their status. Returns list of (node_id, ok, error)."""
        result = await session.execute(select(ReplicationNode).where(ReplicationNode.status != "disabled"))
        nodes = result.scalars().all()
        outcomes: list[tuple[str, bool, str | None]] = []
        async with httpx.AsyncClient(timeout=REPL_TIMEOUT) as client:
            for node in nodes:
                ok, err = await self._ping_node(client, node)
                node.status = "active" if ok else "unhealthy"
                node.last_heartbeat = datetime.now(timezone.utc)
                outcomes.append((node.id, ok, err))
        await session.flush()
        return outcomes

    async def _ping_node(self, client: httpx.AsyncClient, node: ReplicationNode) -> tuple[bool, str | None]:
        try:
            resp = await client.get(
                f"{node.endpoint_url}/api/v1/replication/heartbeat",
                headers={**DEFAULT_HEADERS, "X-Node-Auth": node.auth_token_hash},
            )
            return resp.status_code == 204, None
        except Exception as exc:
            return False, str(exc)

    async def sync_record(
        self,
        session: AsyncSession,
        record: Record,
        nodes: list[ReplicationNode] | None = None,
    ) -> list[ReplicationLog]:
        """Push *record* ciphertext to all active standby nodes; return log entries."""
        if nodes is None:
            result = await session.execute(select(ReplicationNode).where(ReplicationNode.status == "active"))
            nodes = result.scalars().all()

        if not nodes:
            return []

        ciphertext = await self._blob.read(record.blob_path)
        checksum = _checksum(ciphertext)
        metadata = {
            "id": record.id,
            "owner_id": record.owner_id,
            "cipher_name": record.cipher_name,
            "encrypted_dek": record.encrypted_dek,
            "integrity_token": record.integrity_token,
            "searchable_indices": record.searchable_indices,
            "he_fields": record.he_fields,
            "size_bytes": record.size_bytes,
            "version": record.version,
            "previous_version_id": record.previous_version_id,
            "is_deleted": record.is_deleted,
            "created_at": record.created_at.isoformat() if record.created_at else None,
            "updated_at": record.updated_at.isoformat() if record.updated_at else None,
        }

        # Get next sequence number
        seq_result = await session.execute(select(ReplicationLog.sequence_number).order_by(ReplicationLog.sequence_number.desc()))
        max_seq = seq_result.scalar_one_or_none() or 0

        logs: list[ReplicationLog] = []
        async with httpx.AsyncClient(timeout=REPL_TIMEOUT) as client:
            for node in nodes:
                max_seq += 1
                log = ReplicationLog(
                    record_id=record.id,
                    node_id=node.id,
                    status="pending",
                    blob_checksum=checksum,
                    metadata_snapshot=metadata,
                    sequence_number=max_seq,
                )
                session.add(log)
                await session.flush()
                ok, err = await self._push_record(client, node, record.id, ciphertext, metadata, log.sequence_number)
                log.status = "acked" if ok else "failed"
                log.sent_at = datetime.now(timezone.utc)
                log.error_message = err
                if not ok:
                    log.retry_count += 1
                logs.append(log)
        await session.flush()
        return logs

    async def _push_record(
        self,
        client: httpx.AsyncClient,
        node: ReplicationNode,
        record_id: str,
        ciphertext: bytes,
        metadata: dict,
        sequence_number: int,
    ) -> tuple[bool, str | None]:
        import base64

        payload = {
            "record_id": record_id,
            "ciphertext_b64": base64.b64encode(ciphertext).decode(),
            "metadata": metadata,
            "sequence_number": sequence_number,
            "checksum": _checksum(ciphertext),
        }
        try:
            resp = await client.post(
                f"{node.endpoint_url}/api/v1/replication/push",
                json=payload,
                headers={**DEFAULT_HEADERS, "X-Node-Auth": node.auth_token_hash},
            )
            if resp.status_code == 200:
                body = resp.json()
                if body.get("checksum_ok"):
                    return True, None
                return False, "Checksum mismatch on standby"
            return False, f"HTTP {resp.status_code}: {resp.text}"
        except Exception as exc:
            return False, str(exc)

    async def sync_audit_entry(
        self,
        session: AsyncSession,
        entry: AuditLog,
        nodes: list[ReplicationNode] | None = None,
    ) -> list[dict]:
        """Push an audit log entry to standby nodes."""
        if nodes is None:
            result = await session.execute(select(ReplicationNode).where(ReplicationNode.status == "active"))
            nodes = result.scalars().all()

        if not nodes:
            return []

        payload = {
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

        outcomes: list[dict] = []
        async with httpx.AsyncClient(timeout=REPL_TIMEOUT) as client:
            for node in nodes:
                try:
                    resp = await client.post(
                        f"{node.endpoint_url}/api/v1/replication/audit",
                        json=payload,
                        headers={**DEFAULT_HEADERS, "X-Node-Auth": node.auth_token_hash},
                    )
                    outcomes.append({"node_id": node.id, "ok": resp.status_code == 200, "error": None})
                except Exception as exc:
                    outcomes.append({"node_id": node.id, "ok": False, "error": str(exc)})
        return outcomes

    async def retry_pending(self, session: AsyncSession, max_retries: int = 3) -> list[ReplicationLog]:
        """Retry failed/pending replications up to max_retries."""
        result = await session.execute(
            select(ReplicationLog)
            .where(ReplicationLog.status.in_(["pending", "failed"]))
            .where(ReplicationLog.retry_count < max_retries)
            .order_by(ReplicationLog.sequence_number)
        )
        logs = result.scalars().all()
        if not logs:
            return []

        # Fetch nodes map
        node_ids = {log.node_id for log in logs}
        node_result = await session.execute(select(ReplicationNode).where(ReplicationNode.id.in_(node_ids)))
        nodes = {n.id: n for n in node_result.scalars().all()}

        retried: list[ReplicationLog] = []
        async with httpx.AsyncClient(timeout=REPL_TIMEOUT) as client:
            for log in logs:
                node = nodes.get(log.node_id)
                if node is None or node.status != "active":
                    continue
                record_result = await session.execute(select(Record).where(Record.id == log.record_id))
                record = record_result.scalar_one_or_none()
                if record is None:
                    log.status = "failed"
                    log.error_message = "Record no longer exists"
                    continue
                ciphertext = await self._blob.read(record.blob_path)
                ok, err = await self._push_record(
                    client, node, record.id, ciphertext, log.metadata_snapshot, log.sequence_number
                )
                log.retry_count += 1
                log.status = "acked" if ok else "failed"
                log.sent_at = datetime.now(timezone.utc)
                log.error_message = err
                retried.append(log)
        await session.flush()
        return retried
