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
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
    mfa_secret: Mapped[str | None] = mapped_column(Text)

    sessions: Mapped[list["Session"]] = relationship(back_populates="user", lazy="selectin")
    audit_entries: Mapped[list["AuditLog"]] = relationship(back_populates="user", lazy="selectin")


class Session(Base):
    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    refresh_token_hash: Mapped[str] = mapped_column(Text, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    revoked: Mapped[bool] = mapped_column(default=False)

    user: Mapped["User"] = relationship(back_populates="sessions")


class Record(Base):
    __tablename__ = "records"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    owner_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    blob_path: Mapped[str] = mapped_column(Text, nullable=False)
    cipher_name: Mapped[str] = mapped_column(String(32), nullable=False)
    encrypted_dek: Mapped[dict] = mapped_column(JSON, nullable=False)
    integrity_token: Mapped[dict] = mapped_column(JSON, nullable=False)
    searchable_indices: Mapped[dict | None] = mapped_column(JSON)
    size_bytes: Mapped[int] = mapped_column(default=0)
    version: Mapped[int] = mapped_column(default=1)
    previous_version_id: Mapped[str | None] = mapped_column(ForeignKey("records.id"), nullable=True)
    is_deleted: Mapped[bool] = mapped_column(default=False)
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

    user: Mapped["User | None"] = relationship(foreign_keys=[actor_id])

    __table_args__ = (
        Index("idx_audit_actor", "actor_id"),
        Index("idx_audit_action", "action"),
        Index("idx_audit_resource", "resource_type", "resource_id"),
        Index("idx_audit_timestamp", "timestamp"),
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


async def init_db() -> None:
    """Create all metadata tables."""
    from cryptodb.db.connection import _engine

    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
