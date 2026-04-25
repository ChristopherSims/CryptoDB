"""Core engine: orchestrates crypto, storage, ledger, and auth."""

import base64
import json
import logging
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cryptodb.auth.acl import can_access
from cryptodb.auth.rbac import has_permission
from cryptodb.config import settings
from cryptodb.crypto.envelope import Envelope, EnvelopeCipher
from cryptodb.crypto.integrity import IntegrityToken, compute_hmac, verify_hmac
from cryptodb.crypto.keystore import MasterKeyStore
from cryptodb.crypto.searchable import SearchableCipher, SearchableIndex
from cryptodb.db.metadata import AuditLog, Record, User
from cryptodb.ledger.chain import HashChain
from cryptodb.storage.blob import BlobStore
from cryptodb.storage.compression import compress, decompress

logger = logging.getLogger(__name__)


class CryptoDBEngine:
    """The main orchestrator for all CryptoDB operations."""

    @staticmethod
    async def load_chain(session: AsyncSession) -> HashChain:
        """Load existing audit entries from DB to reconstruct the hash chain."""
        result = await session.execute(
            select(AuditLog).order_by(AuditLog.entry_number)
        )
        rows = result.scalars().all()
        chain = HashChain()
        for row in rows:
            # Manually reconstruct; append will recompute hash
            chain._entries.append(
                chain._make_entry(
                    entry_number=row.entry_number,
                    timestamp=row.timestamp,
                    actor_id=row.actor_id,
                    action=row.action,
                    resource_type=row.resource_type,
                    resource_id=row.resource_id,
                    result=row.result,
                    details=row.details,
                    client_ip=row.client_ip,
                    session_id=row.session_id,
                    previous_hash=row.previous_hash,
                    entry_hash=row.entry_hash,
                )
            )
            chain._last_hash = row.entry_hash
        return chain

    def __init__(
        self,
        master_key: bytes,
        blob_store: BlobStore | None = None,
        hash_chain: HashChain | None = None,
    ) -> None:
        self._env = EnvelopeCipher(master_key)
        self._blob = blob_store or BlobStore()
        self._chain = hash_chain or HashChain()
        self._search_key = master_key  # In production, derive a separate key
        self._integ_key = master_key  # In production, derive a separate key

    async def put(
        self,
        session: AsyncSession,
        user: User,
        plaintext: bytes,
        cipher_name: str | None = None,
        compress_algo: str = "zstd",
        searchable_fields: dict[str, str] | None = None,
    ) -> Record:
        """Encrypt and store a record; return the DB row."""
        if not has_permission(user, "create"):
            raise PermissionError("User cannot create records")

        # Compress then encrypt
        compressed = compress(plaintext, algorithm=compress_algo)
        envelope = self._env.encrypt(compressed, cipher_name=cipher_name)

        # Integrity token over ciphertext
        integ = compute_hmac(envelope.ciphertext, self._integ_key)

        # Searchable indices
        indices: dict[str, dict] = {}
        if searchable_fields:
            sc = SearchableCipher(self._search_key)
            for field, value in searchable_fields.items():
                idx = sc.index(value, field_name=field)
                indices[field] = idx.to_dict()

        record = Record(
            owner_id=user.id,
            blob_path="",  # placeholder
            cipher_name=envelope.cipher_name,
            encrypted_dek=envelope.encrypted_dek.to_dict(),
            integrity_token=integ.to_dict(),
            searchable_indices=indices if indices else None,
            size_bytes=len(plaintext),
        )
        session.add(record)
        await session.flush()  # get record.id

        # Write blob
        record.blob_path = await self._blob.write(record.id, envelope.ciphertext)
        await session.flush()

        # Audit
        self._chain.append(
            actor_id=user.id,
            action="create",
            resource_type="record",
            resource_id=record.id,
            details={"cipher": envelope.cipher_name, "size": len(plaintext)},
        )
        await self._persist_audit(session)

        logger.info("Record created", extra={"event": "record_created", "actor": user.username, "record_id": record.id})
        return record

    async def get(
        self,
        session: AsyncSession,
        user: User,
        record_id: str,
    ) -> bytes:
        """Retrieve and decrypt a record."""
        result = await session.execute(select(Record).where(Record.id == record_id, Record.is_deleted == False))  # noqa: E712
        record = result.scalar_one_or_none()
        if record is None:
            raise ValueError("Record not found")
        if not (record.owner_id == user.id or await can_access(session, user, record, "read")):
            if not has_permission(user, "admin"):
                raise PermissionError("Access denied")

        # Read blob
        ciphertext = await self._blob.read(record.blob_path)

        # Verify integrity
        integ = IntegrityToken.from_dict(record.integrity_token)
        if not verify_hmac(ciphertext, integ, self._integ_key):
            raise ValueError("Integrity check failed")

        # Decrypt
        envelope = Envelope(
            encrypted_dek=record.encrypted_dek,
            ciphertext=ciphertext,
            cipher_name=record.cipher_name,
            record_id=record.id,
        )
        compressed = self._env.decrypt(envelope)
        plaintext = decompress(compressed)

        # Audit
        self._chain.append(
            actor_id=user.id,
            action="read",
            resource_type="record",
            resource_id=record.id,
            details={"size": record.size_bytes},
        )
        await self._persist_audit(session)

        logger.info("Record read", extra={"event": "record_read", "actor": user.username, "record_id": record.id})
        return plaintext

    async def delete(
        self,
        session: AsyncSession,
        user: User,
        record_id: str,
        secure: bool = False,
    ) -> None:
        """Soft-delete a record; optionally shred blob."""
        result = await session.execute(select(Record).where(Record.id == record_id))
        record = result.scalar_one_or_none()
        if record is None:
            raise ValueError("Record not found")
        if not (record.owner_id == user.id or await can_access(session, user, record, "delete")):
            if not has_permission(user, "admin"):
                raise PermissionError("Access denied")

        record.is_deleted = True
        await session.flush()

        if secure:
            await self._blob.delete(record.blob_path)

        self._chain.append(
            actor_id=user.id,
            action="delete",
            resource_type="record",
            resource_id=record.id,
            details={"secure": secure},
        )
        await self._persist_audit(session)

        logger.info("Record deleted", extra={"event": "record_deleted", "actor": user.username, "record_id": record_id})

    async def audit_log(self, session: AsyncSession, user: User) -> list[dict]:
        """Return audit entries for admins/auditors."""
        if not has_permission(user, "audit"):
            raise PermissionError("Access denied")

        result = await session.execute(
            select(AuditLog).order_by(AuditLog.entry_number)
        )
        rows = result.scalars().all()
        return [
            {
                "entry_number": r.entry_number,
                "timestamp": r.timestamp.isoformat(),
                "actor_id": r.actor_id,
                "action": r.action,
                "resource_type": r.resource_type,
                "resource_id": r.resource_id,
                "result": r.result,
                "details": r.details,
                "client_ip": r.client_ip,
                "previous_hash": r.previous_hash,
                "entry_hash": r.entry_hash,
            }
            for r in rows
        ]

    async def verify_ledger(self) -> list[tuple[int, str]]:
        """Verify the in-memory hash chain."""
        return self._chain.verify()

    async def _persist_audit(self, session: AsyncSession) -> None:
        """Flush in-memory ledger entries to the database."""
        entries = self._chain.get_entries()
        # Find highest persisted entry_number
        result = await session.execute(select(AuditLog.entry_number).order_by(AuditLog.entry_number.desc()))
        max_num = result.scalar_one_or_none() or 0
        new_entries = [e for e in entries if e.entry_number > max_num]
        for e in new_entries:
            log = AuditLog(
                entry_number=e.entry_number,
                timestamp=e.timestamp,
                actor_id=e.actor_id,
                action=e.action,
                resource_type=e.resource_type,
                resource_id=e.resource_id,
                result=e.result,
                details=e.details,
                client_ip=e.client_ip,
                session_id=e.session_id,
                previous_hash=e.previous_hash,
                entry_hash=e.entry_hash,
            )
            session.add(log)
        await session.flush()
