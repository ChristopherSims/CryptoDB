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
from cryptodb.crypto.he import HEEncryptedNumber, HEKeyPair, PaillierHE
from cryptodb.crypto.integrity import IntegrityToken, compute_hmac, verify_hmac
from cryptodb.crypto.keystore import MasterKeyStore
from cryptodb.crypto.searchable import SearchableCipher, SearchableIndex
from cryptodb.db.metadata import AuditLog, Record, User
from cryptodb.ledger.chain import HashChain
from cryptodb.replication.engine import ReplicationEngine
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
        replication_engine: ReplicationEngine | None = None,
    ) -> None:
        self._env = EnvelopeCipher(master_key)
        self._blob = blob_store or BlobStore()
        self._chain = hash_chain or HashChain()
        self._search_key = master_key  # In production, derive a separate key
        self._integ_key = master_key  # In production, derive a separate key
        self._master_key = master_key
        self._he: PaillierHE | None = None
        self._repl = replication_engine

    def _get_he(self) -> PaillierHE:
        """Return cached PaillierHE instance."""
        if self._he is None:
            raise RuntimeError("HE keypair not initialized")
        return self._he

    def init_he_keypair(self) -> HEKeyPair:
        """Generate a new Paillier keypair and encrypt the private key under master KEK."""
        pub, priv = PaillierHE.generate_keypair()
        priv_bytes = PaillierHE.serialize_private_key(priv)
        # Encrypt private key with AES-256-GCM using master key
        from cryptodb.crypto.ciphers import AES256GCM
        aes = AES256GCM(self._master_key)
        enc_priv = aes.encrypt(priv_bytes)
        he_keypair = HEKeyPair(
            public_key_n=pub.n,
            encrypted_private_key=enc_priv,
        )
        self._he = PaillierHE.from_keypair(pub, priv)
        return he_keypair

    def load_he_keypair(self, he_keypair: HEKeyPair) -> PaillierHE:
        """Load a Paillier keypair, decrypting the private key."""
        pub = PaillierHE.from_public_key(he_keypair.public_key_n)._public_key
        from cryptodb.crypto.ciphers import AES256GCM
        aes = AES256GCM(self._master_key)
        priv_bytes = aes.decrypt(he_keypair.encrypted_private_key)
        priv = PaillierHE.deserialize_private_key(pub, priv_bytes)
        self._he = PaillierHE.from_keypair(pub, priv)
        return self._he

    async def put(
        self,
        session: AsyncSession,
        user: User,
        plaintext: bytes,
        cipher_name: str | None = None,
        compress_algo: str = "zstd",
        searchable_fields: dict[str, str] | None = None,
        he_fields: dict[str, int | float] | None = None,
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

        # HE fields
        he_data: dict[str, dict] | None = None
        if he_fields and self._he is not None:
            he_data = {}
            for field, value in he_fields.items():
                enc = self._he.encrypt(value)
                he_data[field] = enc.to_dict()

        record = Record(
            owner_id=user.id,
            blob_path="",  # placeholder
            cipher_name=envelope.cipher_name,
            encrypted_dek=envelope.encrypted_dek.to_dict(),
            integrity_token=integ.to_dict(),
            searchable_indices=indices if indices else None,
            he_fields=he_data,
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
            details={"cipher": envelope.cipher_name, "size": len(plaintext), "he_fields": list(he_fields.keys()) if he_fields else []},
        )
        await self._persist_audit(session)

        # Replication
        if settings.replication_enabled and self._repl is not None:
            await self._repl.sync_record(session, record)

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

        from cryptodb.crypto.envelope import EncryptedDataKey

        # Decrypt
        envelope = Envelope(
            encrypted_dek=EncryptedDataKey.from_dict(record.encrypted_dek),
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

        # Replication: sync deletion metadata so standbys know it's deleted
        if settings.replication_enabled and self._repl is not None:
            await self._repl.sync_record(session, record)

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

    async def he_sum(
        self,
        session: AsyncSession,
        user: User,
        record_ids: list[str],
        field: str,
    ) -> HEEncryptedNumber:
        """Compute an encrypted sum of *field* across *record_ids* without decrypting."""
        if not has_permission(user, "read"):
            raise PermissionError("Access denied")
        if self._he is None:
            raise RuntimeError("HE not initialized")

        result: HEEncryptedNumber | None = None
        for rid in record_ids:
            res = await session.execute(select(Record).where(Record.id == rid, Record.is_deleted == False))  # noqa: E712
            record = res.scalar_one_or_none()
            if record is None or record.he_fields is None:
                continue
            if field not in record.he_fields:
                continue
            if not (record.owner_id == user.id or await can_access(session, user, record, "read")):
                if not has_permission(user, "admin"):
                    continue
            enc = HEEncryptedNumber.from_dict(record.he_fields[field])
            if result is None:
                result = enc
            else:
                result = self._he.add(result, enc)

        if result is None:
            raise ValueError("No valid HE fields found for aggregation")
        return result

    async def he_decrypt_aggregate(
        self,
        session: AsyncSession,
        user: User,
        enc: HEEncryptedNumber,
    ) -> int | float:
        """Decrypt an aggregated HE value. Requires private key."""
        if not has_permission(user, "audit"):
            raise PermissionError("Access denied")
        if self._he is None or not self._he.has_private_key():
            raise RuntimeError("HE private key not available")
        return self._he.decrypt(enc)

    async def _persist_audit(self, session: AsyncSession) -> None:
        """Flush in-memory ledger entries to the database."""
        from sqlalchemy import func
        entries = self._chain.get_entries()
        # Find highest persisted entry_number
        result = await session.execute(select(func.max(AuditLog.entry_number)))
        max_num = result.scalar_one_or_none() or 0
        new_entries = [e for e in entries if e.entry_number > max_num]
        audit_rows: list[AuditLog] = []
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
            audit_rows.append(log)
        await session.flush()

        # Replicate audit entries
        if settings.replication_enabled and self._repl is not None and audit_rows:
            for row in audit_rows:
                await self._repl.sync_audit_entry(session, row)
