"""SQLAlchemy models for metadata store."""

import uuid
from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, ForeignKey, Index, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    email: Mapped[str | None] = mapped_column(String(256), unique=True)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    role: Mapped[str] = mapped_column(String(32), default="reader", nullable=False)
    is_active: Mapped[bool] = mapped_column(default=True)
    hardware_mfa_required: Mapped[bool] = mapped_column(default=False)
    quota_bytes: Mapped[int | None] = mapped_column(default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
    mfa_secret: Mapped[str | None] = mapped_column(Text)

    sessions: Mapped[list["Session"]] = relationship(back_populates="user", lazy="selectin")
    audit_entries: Mapped[list["AuditLog"]] = relationship(back_populates="user", lazy="selectin")
    hardware_credentials: Mapped[list["HardwareTokenCredential"]] = relationship(back_populates="user", lazy="selectin")


class Session(Base):
    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    refresh_token_hash: Mapped[str] = mapped_column(Text, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    revoked: Mapped[bool] = mapped_column(default=False)

    user: Mapped["User"] = relationship(back_populates="sessions")


class TokenBlacklist(Base):
    __tablename__ = "token_blacklist"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    jti: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))


class Record(Base):
    __tablename__ = "records"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    owner_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    blob_path: Mapped[str] = mapped_column(Text, nullable=False)
    cipher_name: Mapped[str] = mapped_column(String(32), nullable=False)
    master_key_id: Mapped[str | None] = mapped_column(String(64), default=None)
    encrypted_dek: Mapped[dict] = mapped_column(JSON, nullable=False)
    integrity_token: Mapped[dict] = mapped_column(JSON, nullable=False)
    searchable_indices: Mapped[dict | None] = mapped_column(JSON)
    he_fields: Mapped[dict | None] = mapped_column(JSON)
    size_bytes: Mapped[int] = mapped_column(default=0)
    content_type: Mapped[str | None] = mapped_column(String(128), default=None)
    tags: Mapped[dict | None] = mapped_column(JSON)
    version: Mapped[int] = mapped_column(default=1)
    previous_version_id: Mapped[str | None] = mapped_column(ForeignKey("records.id"), nullable=True)
    is_deleted: Mapped[bool] = mapped_column(default=False)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime, default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    owner: Mapped["User"] = relationship(foreign_keys=[owner_id])
    previous_version: Mapped["Record | None"] = relationship(remote_side="Record.id")
    acl_entries: Mapped[list["RecordACL"]] = relationship(back_populates="record", lazy="selectin")

    __table_args__ = (
        Index("idx_records_owner", "owner_id"),
        Index("idx_records_deleted", "is_deleted"),
        Index("idx_records_deleted_at", "deleted_at"),
        Index("idx_records_content_type", "content_type"),
    )


class RecordACL(Base):
    __tablename__ = "record_acls"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    record_id: Mapped[str] = mapped_column(ForeignKey("records.id"), nullable=False)
    user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    role: Mapped[str | None] = mapped_column(String(32), nullable=True)
    permission: Mapped[str] = mapped_column(String(16), nullable=False)  # read, write, delete
    granted_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    granted_by: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)

    record: Mapped["Record"] = relationship(back_populates="acl_entries")


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    entry_number: Mapped[int] = mapped_column(nullable=False, unique=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    actor_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(32), nullable=False)
    resource_id: Mapped[str | None] = mapped_column(String(36))
    result: Mapped[str] = mapped_column(String(16), default="success")
    details: Mapped[dict | None] = mapped_column(JSON)
    client_ip: Mapped[str | None] = mapped_column(String(64))
    session_id: Mapped[str | None] = mapped_column(String(36))
    previous_hash: Mapped[str] = mapped_column(Text, nullable=False)
    entry_hash: Mapped[str] = mapped_column(Text, nullable=False)
    request_id: Mapped[str | None] = mapped_column(String(64))

    user: Mapped["User | None"] = relationship(foreign_keys=[actor_id])

    __table_args__ = (
        Index("idx_audit_actor", "actor_id"),
        Index("idx_audit_action", "action"),
        Index("idx_audit_resource", "resource_type", "resource_id"),
        Index("idx_audit_timestamp", "timestamp"),
        Index("idx_audit_request_id", "request_id"),
    )


class LedgerCheckpoint(Base):
    __tablename__ = "ledger_checkpoints"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    checkpoint_number: Mapped[int] = mapped_column(nullable=False, unique=True)
    last_entry_hash: Mapped[str] = mapped_column(Text, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    signature: Mapped[str] = mapped_column(Text, nullable=False)

    __table_args__ = (
        Index("idx_checkpoint_number", "checkpoint_number"),
    )


class KeyRotationLog(Base):
    __tablename__ = "key_rotation_log"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    key_id: Mapped[str] = mapped_column(String(64), nullable=False)
    key_type: Mapped[str] = mapped_column(String(16), nullable=False)  # kek, dek
    old_key_id: Mapped[str | None] = mapped_column(String(64))
    new_key_id: Mapped[str] = mapped_column(String(64), nullable=False)
    affected_records: Mapped[int] = mapped_column(default=0)
    rotated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    rotated_by: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    status: Mapped[str] = mapped_column(String(16), default="pending")  # pending, complete, failed


class HardwareTokenCredential(Base):
    __tablename__ = "hardware_token_credentials"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    credential_id: Mapped[str] = mapped_column(Text, nullable=False)  # base64url encoded credential ID
    public_key: Mapped[str] = mapped_column(Text, nullable=False)  # base64url encoded COSE public key
    token_type: Mapped[str] = mapped_column(String(16), nullable=False)  # fido2, tpm
    sign_count: Mapped[int] = mapped_column(default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime)
    name: Mapped[str] = mapped_column(String(128), default="Primary Token")

    user: Mapped["User"] = relationship(back_populates="hardware_credentials")

    __table_args__ = (
        Index("idx_hwcred_user", "user_id"),
        Index("idx_hwcred_cid", "credential_id"),
    )


class ReplicationNode(Base):
    __tablename__ = "replication_nodes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    endpoint_url: Mapped[str] = mapped_column(String(512), nullable=False)
    auth_token_hash: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(16), default="active")  # active, unhealthy, disabled
    last_heartbeat: Mapped[datetime | None] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    is_primary: Mapped[bool] = mapped_column(default=False)

    __table_args__ = (
        Index("idx_rep_nodes_status", "status"),
    )


class ReplicationLog(Base):
    __tablename__ = "replication_log"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    record_id: Mapped[str] = mapped_column(String(36), nullable=False)
    node_id: Mapped[str] = mapped_column(ForeignKey("replication_nodes.id"), nullable=False)
    status: Mapped[str] = mapped_column(String(16), default="pending")  # pending, sent, failed, acked
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    sent_at: Mapped[datetime | None] = mapped_column(DateTime)
    retry_count: Mapped[int] = mapped_column(default=0)
    error_message: Mapped[str | None] = mapped_column(Text)
    blob_checksum: Mapped[str] = mapped_column(String(64), nullable=False)
    metadata_snapshot: Mapped[dict] = mapped_column(JSON, nullable=False)
    sequence_number: Mapped[int] = mapped_column(nullable=False)

    node: Mapped["ReplicationNode"] = relationship()

    __table_args__ = (
        Index("idx_replog_node", "node_id"),
        Index("idx_replog_status", "status"),
        Index("idx_replog_seq", "sequence_number"),
    )


class ReplicationDeadLetter(Base):
    __tablename__ = "replication_dead_letter"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    record_id: Mapped[str] = mapped_column(String(36), nullable=False)
    node_id: Mapped[str] = mapped_column(ForeignKey("replication_nodes.id"), nullable=False)
    metadata_snapshot: Mapped[dict] = mapped_column(JSON, nullable=False)
    blob_checksum: Mapped[str] = mapped_column(String(64), nullable=False)
    sequence_number: Mapped[int] = mapped_column(nullable=False)
    error_history: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

    node: Mapped["ReplicationNode"] = relationship()

    __table_args__ = (
        Index("idx_dl_node", "node_id"),
        Index("idx_dl_record", "record_id"),
    )
