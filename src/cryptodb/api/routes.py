"""FastAPI routes for CryptoDB."""

import base64

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import HTTPAuthorizationCredentials
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cryptodb.api.dependencies import get_current_user, get_db, security
from cryptodb.auth.users import authenticate_user, create_user
from cryptodb.auth.session import create_session
from cryptodb.auth.rbac import require_permission
from cryptodb.config import settings
from cryptodb.crypto.keystore import MasterKeyStore
from cryptodb.compliance.reports import (
    gdpr_right_to_erasure_report,
    hipaa_access_report,
    soc2_evidence_export,
)
from cryptodb.db.connection import init_db
from cryptodb.db.metadata import User
from cryptodb.engine import CryptoDBEngine
from cryptodb.ledger.verify import TamperError, verify_ledger

from cryptodb.replication.engine import ReplicationEngine

router = APIRouter()

_engine: CryptoDBEngine | None = None
_repl_engine: ReplicationEngine | None = None


def get_engine() -> CryptoDBEngine:
    if _engine is None:
        raise RuntimeError("Engine not initialized")
    return _engine


class PutPayload(BaseModel):
    data_b64: str
    cipher_name: str | None = None
    compress: str = "zstd"
    searchable: dict[str, str] | None = None
    he_fields: dict[str, float] | None = None
    content_type: str | None = None
    tags: dict[str, str] | None = None


class PutResponse(BaseModel):
    record_id: str
    size_bytes: int


class GetResponse(BaseModel):
    data_b64: str
    record_id: str


class HESumPayload(BaseModel):
    record_ids: list[str]
    field: str


class HESumResponse(BaseModel):
    encrypted_sum: dict[str, int]


class HEDecryptPayload(BaseModel):
    encrypted_sum: dict[str, int]


class HEDecryptResponse(BaseModel):
    decrypted_value: float


class RegisterNodePayload(BaseModel):
    name: str
    endpoint_url: str


class RegisterNodeResponse(BaseModel):
    node_id: str
    auth_token: str
    endpoint_url: str


class ReplicationPushPayload(BaseModel):
    record_id: str
    ciphertext_b64: str
    metadata: dict
    sequence_number: int
    checksum: str


class ReplicationPushResponse(BaseModel):
    status: str
    checksum_ok: bool


class ReplicationAuditPayload(BaseModel):
    entry_number: int
    timestamp: str
    actor_id: str | None
    action: str
    resource_type: str
    resource_id: str | None
    result: str
    details: dict | None
    client_ip: str | None
    session_id: str | None
    previous_hash: str
    entry_hash: str


class LoginPayload(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class HardwareRegisterBeginPayload(BaseModel):
    name: str = "Primary Token"


class HardwareRegisterBeginResponse(BaseModel):
    public_credential_options: dict
    challenge_token: str


class HardwareRegisterFinishPayload(BaseModel):
    challenge_token: str
    client_response: dict


class HardwareRegisterFinishResponse(BaseModel):
    credential_id: str
    status: str


class HardwareAuthenticateBeginResponse(BaseModel):
    public_request_options: dict
    challenge_token: str


class HardwareAuthenticateFinishPayload(BaseModel):
    challenge_token: str
    client_response: dict


class SealMasterKeyPayload(BaseModel):
    passphrase: str


class SealMasterKeyResponse(BaseModel):
    sealed_blob_b64: str
    method: str


class SearchPayload(BaseModel):
    field_name: str
    token_plaintext: str


class SearchResponse(BaseModel):
    record_ids: list[str]


class ListRecordItem(BaseModel):
    id: str
    owner_id: str
    created_at: str
    size_bytes: int
    cipher_name: str
    content_type: str | None = None


class GrantPayload(BaseModel):
    user_id: str | None = None
    role: str | None = None
    permission: str  # read, write, delete


class GrantResponse(BaseModel):
    grant_id: str
    permission: str
    user_id: str | None = None
    role: str | None = None


class UserListItem(BaseModel):
    id: str
    username: str
    email: str | None = None
    role: str
    is_active: bool
    created_at: str


class PatchRolePayload(BaseModel):
    role: str


class RefreshPayload(BaseModel):
    refresh_token: str


class HealthResponse(BaseModel):
    status: str
    engine_ready: bool
    db_connected: bool
    blob_store_writable: bool
    disk_usage_percent: float
    ledger_integrity_ok: bool


@router.post("/init", status_code=status.HTTP_204_NO_CONTENT)
async def init_database() -> None:
    await init_db()


@router.post("/auth/register")
async def register(
    payload: LoginPayload,
    session: AsyncSession = Depends(get_db),  # noqa: B008
) -> dict:
    user = await create_user(session, payload.username, payload.password)
    await session.commit()
    return {"user_id": user.id, "username": user.username}


@router.post("/auth/login", response_model=LoginResponse)
async def login(
    payload: LoginPayload,
    session: AsyncSession = Depends(get_db),  # noqa: B008
) -> LoginResponse:
    user = await authenticate_user(session, payload.username, payload.password)
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    access, refresh = await create_session(session, user)
    await session.commit()
    return LoginResponse(access_token=access, refresh_token=refresh)


@router.post("/auth/logout")
async def logout(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),  # noqa: B008
    session: AsyncSession = Depends(get_db),  # noqa: B008
) -> dict:
    from cryptodb.auth.session import revoke_token
    token = credentials.credentials
    ok = await revoke_token(session, token)
    await session.commit()
    return {"status": "logged_out" if ok else "failed"}


@router.post("/auth/refresh", response_model=LoginResponse)
async def refresh(
    payload: RefreshPayload,
    session: AsyncSession = Depends(get_db),  # noqa: B008
) -> LoginResponse:
    from cryptodb.auth.session import rotate_refresh_token
    result = await rotate_refresh_token(session, payload.refresh_token)
    if result is None:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")
    access, refresh = result
    await session.commit()
    return LoginResponse(access_token=access, refresh_token=refresh)


@router.post("/records", response_model=PutResponse)
async def create_record(
    payload: PutPayload,
    user: User = Depends(get_current_user),  # noqa: B008
    session: AsyncSession = Depends(get_db),  # noqa: B008
) -> PutResponse:
    import base64
    engine = get_engine()
    plaintext = base64.b64decode(payload.data_b64)
    max_size = settings.max_record_size_mb * 1024 * 1024
    if len(plaintext) > max_size:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Record size {len(plaintext)} bytes exceeds max {max_size} bytes",
        )
    record = await engine.put(
        session, user, plaintext,
        cipher_name=payload.cipher_name,
        compress_algo=payload.compress,
        searchable_fields=payload.searchable,
        he_fields=payload.he_fields,
        content_type=getattr(payload, "content_type", None),
        tags=getattr(payload, "tags", None),
    )
    await session.commit()
    return PutResponse(record_id=record.id, size_bytes=record.size_bytes)


@router.get("/records/{record_id}", response_model=GetResponse)
async def read_record(
    record_id: str,
    user: User = Depends(get_current_user),  # noqa: B008
    session: AsyncSession = Depends(get_db),  # noqa: B008
) -> GetResponse:
    import base64
    engine = get_engine()
    plaintext = await engine.get(session, user, record_id)
    await session.commit()
    return GetResponse(data_b64=base64.b64encode(plaintext).decode(), record_id=record_id)


@router.delete("/records/{record_id}")
async def delete_record(
    record_id: str,
    user: User = Depends(get_current_user),  # noqa: B008
    session: AsyncSession = Depends(get_db),  # noqa: B008
    secure: bool = False,
) -> dict:
    engine = get_engine()
    await engine.delete(session, user, record_id, secure=secure)
    await session.commit()
    return {"status": "deleted", "record_id": record_id}


@router.post("/records/search", response_model=SearchResponse)
async def search_records(
    payload: SearchPayload,
    user: User = Depends(get_current_user),  # noqa: B008
    session: AsyncSession = Depends(get_db),  # noqa: B008
) -> SearchResponse:
    engine = get_engine()
    record_ids = await engine.search_by_index(session, user, payload.field_name, payload.token_plaintext)
    return SearchResponse(record_ids=record_ids)


@router.get("/records", response_model=list[ListRecordItem])
async def list_records(
    page: int = 1,
    page_size: int = 20,
    user: User = Depends(get_current_user),  # noqa: B008
    session: AsyncSession = Depends(get_db),  # noqa: B008
) -> list[ListRecordItem]:
    engine = get_engine()
    items = await engine.list_records(session, user, page=page, page_size=page_size)
    return [
        ListRecordItem(
            id=r["id"],
            owner_id=r["owner_id"],
            created_at=r["created_at"],
            size_bytes=r["size_bytes"],
            cipher_name=r["cipher_name"],
            content_type=r.get("content_type"),
        )
        for r in items
    ]


@router.post("/records/{record_id}/grants", response_model=GrantResponse)
async def grant_record_access(
    record_id: str,
    payload: GrantPayload,
    user: User = Depends(get_current_user),  # noqa: B008
    session: AsyncSession = Depends(get_db),  # noqa: B008
) -> GrantResponse:
    from cryptodb.auth.acl import grant_access
    from cryptodb.db.metadata import Record
    result = await session.execute(select(Record).where(Record.id == record_id))
    record = result.scalar_one_or_none()
    if record is None:
        raise HTTPException(status_code=404, detail="Record not found")
    if record.owner_id != user.id and not has_permission(user, "admin"):
        raise HTTPException(status_code=403, detail="Only owner or admin can manage grants")
    target_user = None
    if payload.user_id:
        from cryptodb.db.metadata import User as UserModel
        ures = await session.execute(select(UserModel).where(UserModel.id == payload.user_id))
        target_user = ures.scalar_one_or_none()
        if target_user is None:
            raise HTTPException(status_code=404, detail="Target user not found")
    acl = await grant_access(
        session, record, user, payload.permission,
        user=target_user, role=payload.role,
    )
    await session.commit()
    return GrantResponse(
        grant_id=acl.id,
        permission=acl.permission,
        user_id=acl.user_id,
        role=acl.role,
    )


@router.delete("/records/{record_id}/grants/{grant_id}")
async def revoke_record_access(
    record_id: str,
    grant_id: str,
    user: User = Depends(get_current_user),  # noqa: B008
    session: AsyncSession = Depends(get_db),  # noqa: B008
) -> dict:
    from cryptodb.db.metadata import Record, RecordACL
    result = await session.execute(select(Record).where(Record.id == record_id))
    record = result.scalar_one_or_none()
    if record is None:
        raise HTTPException(status_code=404, detail="Record not found")
    if record.owner_id != user.id and not has_permission(user, "admin"):
        raise HTTPException(status_code=403, detail="Only owner or admin can manage grants")
    res = await session.execute(select(RecordACL).where(RecordACL.id == grant_id, RecordACL.record_id == record_id))
    acl = res.scalar_one_or_none()
    if acl is None:
        raise HTTPException(status_code=404, detail="Grant not found")
    await session.delete(acl)
    await session.commit()
    return {"status": "revoked", "grant_id": grant_id}


@router.get("/records/{record_id}/grants")
async def list_record_grants(
    record_id: str,
    user: User = Depends(get_current_user),  # noqa: B008
    session: AsyncSession = Depends(get_db),  # noqa: B008
) -> list[dict]:
    from cryptodb.db.metadata import Record
    result = await session.execute(select(Record).where(Record.id == record_id))
    record = result.scalar_one_or_none()
    if record is None:
        raise HTTPException(status_code=404, detail="Record not found")
    if record.owner_id != user.id and not has_permission(user, "admin"):
        if not any(acl.user_id == user.id for acl in record.acl_entries):
            raise HTTPException(status_code=403, detail="Access denied")
    return [
        {
            "id": acl.id,
            "user_id": acl.user_id,
            "role": acl.role,
            "permission": acl.permission,
            "granted_at": acl.granted_at.isoformat() if acl.granted_at else None,
            "granted_by": acl.granted_by,
        }
        for acl in record.acl_entries
    ]


@router.get("/audit")
async def list_audit(
    user: User = Depends(get_current_user),  # noqa: B008
    session: AsyncSession = Depends(get_db),  # noqa: B008
) -> list[dict]:
    engine = get_engine()
    return await engine.audit_log(session, user)


@router.post("/master-key")
async def setup_master_key(
    passphrase: str,
    user: User = Depends(get_current_user),  # noqa: B008
    session: AsyncSession = Depends(get_db),  # noqa: B008
) -> dict:
    require_permission(user, "admin")
    ks = MasterKeyStore()
    kek = ks.create_master_key(passphrase)
    chain = await CryptoDBEngine.load_chain(session)
    global _engine, _repl_engine
    _repl_engine = ReplicationEngine() if settings.replication_enabled else None
    _engine = CryptoDBEngine(kek, hash_chain=chain, replication_engine=_repl_engine)
    return {"status": "created", "key_id": settings.master_key_id}


@router.post("/master-key/unlock")
async def unlock_master_key(
    passphrase: str,
    user: User = Depends(get_current_user),  # noqa: B008
    session: AsyncSession = Depends(get_db),  # noqa: B008
) -> dict:
    require_permission(user, "admin")
    ks = MasterKeyStore()
    kek = ks.load_master_key(passphrase)
    chain = await CryptoDBEngine.load_chain(session)
    global _engine, _repl_engine
    _repl_engine = ReplicationEngine() if settings.replication_enabled else None
    _engine = CryptoDBEngine(kek, hash_chain=chain, replication_engine=_repl_engine)
    return {"status": "unlocked", "key_id": settings.master_key_id}


@router.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    import shutil
    engine = get_engine()
    db_ok = False
    blob_ok = False
    disk_usage = 0.0
    try:
        from cryptodb.db.connection import _ensure_engine
        eng = _ensure_engine()
        async with eng.connect() as conn:
            await conn.execute(select(1))
        db_ok = True
    except Exception:
        pass
    try:
        from cryptodb.storage.blob import BlobStore
        bs = BlobStore()
        blob_ok = await bs.health_check()
    except Exception:
        pass
    try:
        du = shutil.disk_usage(settings.resolved_data_dir)
        disk_usage = round((du.used / du.total) * 100, 2) if du.total else 0.0
    except Exception:
        pass
    ledger_ok = True
    if engine is not None:
        try:
            failures = await engine.verify_ledger()
            ledger_ok = len(failures) == 0
        except Exception:
            ledger_ok = False
    return HealthResponse(
        status="ok",
        engine_ready=_engine is not None,
        db_connected=db_ok,
        blob_store_writable=blob_ok,
        disk_usage_percent=disk_usage,
        ledger_integrity_ok=ledger_ok,
    )


@router.post("/admin/purge-deleted")
async def purge_deleted(
    user: User = Depends(get_current_user),  # noqa: B008
    session: AsyncSession = Depends(get_db),  # noqa: B008
) -> dict:
    """Permanently purge soft-deleted records past retention period."""
    require_permission(user, "admin")
    engine = get_engine()
    count = await engine.purge_soft_deleted(session, user)
    await session.commit()
    return {"purged": count}


@router.post("/ledger/verify")
async def verify_ledger_endpoint(
    user: User = Depends(get_current_user),  # noqa: B008
    session: AsyncSession = Depends(get_db),  # noqa: B008
) -> dict:
    require_permission(user, "audit")
    engine = get_engine()
    failures = await engine.verify_ledger()
    if failures:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"tampered": True, "failures": failures},
        )
    return {"tampered": False, "entries": engine._chain.length}


@router.get("/ledger/export")
async def ledger_export(
    fmt: str = "json",
    start_date: str | None = None,
    end_date: str | None = None,
    user: User = Depends(get_current_user),  # noqa: B008
    session: AsyncSession = Depends(get_db),  # noqa: B008
) -> dict:
    """Export ledger entries within a date range."""
    require_permission(user, "audit")
    engine = get_engine()
    entries = await engine.audit_log(session, user)
    filtered = entries
    if start_date or end_date:
        from datetime import datetime
        if start_date:
            start = datetime.fromisoformat(start_date)
            filtered = [e for e in filtered if e.get("timestamp") and datetime.fromisoformat(e["timestamp"]) >= start]
        if end_date:
            end = datetime.fromisoformat(end_date)
            filtered = [e for e in filtered if e.get("timestamp") and datetime.fromisoformat(e["timestamp"]) <= end]
    if fmt == "csv":
        import csv
        import io
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=["entry_number", "timestamp", "actor_id", "action", "resource_type", "resource_id", "result", "entry_hash"])
        writer.writeheader()
        for e in filtered:
            writer.writerow({k: e.get(k, "") for k in writer.fieldnames})
        return {"format": "csv", "data": buf.getvalue()}
    return {"format": "json", "data": filtered}


# ---------------------------------------------------------------------------
# User management (admin only)
# ---------------------------------------------------------------------------


@router.get("/users", response_model=list[UserListItem])
async def list_users(
    user: User = Depends(get_current_user),  # noqa: B008
    session: AsyncSession = Depends(get_db),  # noqa: B008
) -> list[UserListItem]:
    require_permission(user, "admin")
    result = await session.execute(select(User).order_by(User.created_at))
    rows = result.scalars().all()
    return [
        UserListItem(
            id=u.id,
            username=u.username,
            email=u.email,
            role=u.role,
            is_active=u.is_active,
            created_at=u.created_at.isoformat() if u.created_at else "",
        )
        for u in rows
    ]


@router.patch("/users/{user_id}/role")
async def set_user_role(
    user_id: str,
    payload: PatchRolePayload,
    user: User = Depends(get_current_user),  # noqa: B008
    session: AsyncSession = Depends(get_db),  # noqa: B008
) -> dict:
    require_permission(user, "admin")
    result = await session.execute(select(User).where(User.id == user_id))
    target = result.scalar_one_or_none()
    if target is None:
        raise HTTPException(status_code=404, detail="User not found")
    target.role = payload.role
    await session.commit()
    return {"status": "updated", "user_id": user_id, "role": payload.role}


@router.delete("/users/{user_id}")
async def delete_user(
    user_id: str,
    user: User = Depends(get_current_user),  # noqa: B008
    session: AsyncSession = Depends(get_db),  # noqa: B008
) -> dict:
    require_permission(user, "admin")
    result = await session.execute(select(User).where(User.id == user_id))
    target = result.scalar_one_or_none()
    if target is None:
        raise HTTPException(status_code=404, detail="User not found")
    target.is_active = False
    await session.commit()
    return {"status": "disabled", "user_id": user_id}


@router.post("/users/{user_id}/disable")
async def disable_user(
    user_id: str,
    user: User = Depends(get_current_user),  # noqa: B008
    session: AsyncSession = Depends(get_db),  # noqa: B008
) -> dict:
    require_permission(user, "admin")
    result = await session.execute(select(User).where(User.id == user_id))
    target = result.scalar_one_or_none()
    if target is None:
        raise HTTPException(status_code=404, detail="User not found")
    target.is_active = False
    await session.commit()
    return {"status": "disabled", "user_id": user_id}


@router.get("/compliance/gdpr/{user_id}")
async def gdpr_report(
    user_id: str,
    user: User = Depends(get_current_user),  # noqa: B008
    session: AsyncSession = Depends(get_db),  # noqa: B008
) -> dict:
    require_permission(user, "audit")
    report = await gdpr_right_to_erasure_report(session, user_id)
    return {
        "standard": report.standard,
        "generated_at": report.generated_at.isoformat(),
        "summary": report.summary,
        "findings": report.findings,
    }


@router.get("/compliance/hipaa/{record_id}")
async def hipaa_report(
    record_id: str,
    user: User = Depends(get_current_user),  # noqa: B008
    session: AsyncSession = Depends(get_db),  # noqa: B008
) -> dict:
    require_permission(user, "audit")
    report = await hipaa_access_report(session, record_id)
    return {
        "standard": report.standard,
        "generated_at": report.generated_at.isoformat(),
        "summary": report.summary,
        "findings": report.findings,
    }


@router.get("/compliance/soc2")
async def soc2_report(
    user: User = Depends(get_current_user),  # noqa: B008
    session: AsyncSession = Depends(get_db),  # noqa: B008
) -> dict:
    require_permission(user, "audit")
    report = await soc2_evidence_export(session)
    return {
        "standard": report.standard,
        "generated_at": report.generated_at.isoformat(),
        "summary": report.summary,
        "findings": report.findings,
    }


@router.get("/metrics")
async def metrics_endpoint():
    from cryptodb.api.metrics import get_metrics_response
    data, content_type = get_metrics_response()
    from fastapi import Response
    return Response(content=data, media_type=content_type)


@router.get("/audit/anomalies")
async def audit_anomalies(
    user: User = Depends(get_current_user),  # noqa: B008
    session: AsyncSession = Depends(get_db),  # noqa: B008
) -> list[dict]:
    require_permission(user, "audit")
    engine = get_engine()
    entries = await engine.audit_log(session, user, run_anomaly_detection=True)
    from cryptodb.ledger.anomaly import detect_bulk_access, detect_off_hours
    anomalies = detect_off_hours(entries) + detect_bulk_access(entries)
    return [
        {
            "rule": a.rule,
            "description": a.description,
            "severity": a.severity,
            "actor_id": a.actor_id,
            "timestamp": a.timestamp.isoformat(),
            "details": a.details,
        }
        for a in anomalies
    ]


@router.post("/he/init")
async def init_he(
    user: User = Depends(get_current_user),  # noqa: B008
    session: AsyncSession = Depends(get_db),  # noqa: B008
) -> dict:
    """Generate a Paillier HE keypair. Admin only."""
    require_permission(user, "admin")
    engine = get_engine()
    he_keypair = engine.init_he_keypair()
    return {"status": "created", "public_key_n": str(he_keypair.public_key_n)}


@router.post("/he/sum", response_model=HESumResponse)
async def he_sum_endpoint(
    payload: HESumPayload,
    user: User = Depends(get_current_user),  # noqa: B008
    session: AsyncSession = Depends(get_db),  # noqa: B008
) -> HESumResponse:
    """Compute an encrypted sum of a field across records without decrypting."""
    engine = get_engine()
    result = await engine.he_sum(session, user, payload.record_ids, payload.field)
    return HESumResponse(encrypted_sum=result.to_dict())


@router.post("/he/decrypt", response_model=HEDecryptResponse)
async def he_decrypt_endpoint(
    payload: HEDecryptPayload,
    user: User = Depends(get_current_user),  # noqa: B008
    session: AsyncSession = Depends(get_db),  # noqa: B008
) -> HEDecryptResponse:
    """Decrypt an aggregated HE value. Auditor/admin only."""
    from cryptodb.crypto.he import HEEncryptedNumber
    engine = get_engine()
    enc = HEEncryptedNumber.from_dict(payload.encrypted_sum)
    value = await engine.he_decrypt_aggregate(session, user, enc)
    return HEDecryptResponse(decrypted_value=float(value))


# ---------------------------------------------------------------------------
# Replication endpoints
# ---------------------------------------------------------------------------


@router.post("/replication/nodes", response_model=RegisterNodeResponse)
async def register_standby_node(
    payload: RegisterNodePayload,
    user: User = Depends(get_current_user),  # noqa: B008
    session: AsyncSession = Depends(get_db),  # noqa: B008
) -> RegisterNodeResponse:
    require_permission(user, "admin")
    repl = ReplicationEngine()
    node, token = await repl.register_node(session, user, payload.name, payload.endpoint_url)
    await session.commit()
    return RegisterNodeResponse(node_id=node.id, auth_token=token, endpoint_url=node.endpoint_url)


@router.delete("/replication/nodes/{node_id}")
async def unregister_standby_node(
    node_id: str,
    user: User = Depends(get_current_user),  # noqa: B008
    session: AsyncSession = Depends(get_db),  # noqa: B008
) -> dict:
    require_permission(user, "admin")
    repl = ReplicationEngine()
    await repl.unregister_node(session, user, node_id)
    await session.commit()
    return {"status": "unregistered", "node_id": node_id}


@router.get("/replication/nodes")
async def list_standby_nodes(
    user: User = Depends(get_current_user),  # noqa: B008
    session: AsyncSession = Depends(get_db),  # noqa: B008
) -> list[dict]:
    require_permission(user, "admin")
    repl = ReplicationEngine()
    nodes = await repl.list_nodes(session, user)
    return [
        {
            "id": n.id,
            "name": n.name,
            "endpoint_url": n.endpoint_url,
            "status": n.status,
            "last_heartbeat": n.last_heartbeat.isoformat() if n.last_heartbeat else None,
            "created_at": n.created_at.isoformat(),
            "is_primary": n.is_primary,
        }
        for n in nodes
    ]


@router.post("/replication/health-check")
async def replication_health_check(
    user: User = Depends(get_current_user),  # noqa: B008
    session: AsyncSession = Depends(get_db),  # noqa: B008
) -> list[dict]:
    require_permission(user, "admin")
    repl = ReplicationEngine()
    outcomes = await repl.health_check_nodes(session)
    await session.commit()
    return [
        {"node_id": nid, "healthy": ok, "error": err}
        for nid, ok, err in outcomes
    ]


@router.post("/replication/retry")
async def replication_retry(
    user: User = Depends(get_current_user),  # noqa: B008
    session: AsyncSession = Depends(get_db),  # noqa: B008
) -> list[dict]:
    require_permission(user, "admin")
    repl = ReplicationEngine()
    logs = await repl.retry_pending(session, max_retries=settings.replication_retry_max)
    await session.commit()
    return [
        {
            "log_id": log.id,
            "record_id": log.record_id,
            "node_id": log.node_id,
            "status": log.status,
            "retry_count": log.retry_count,
            "error": log.error_message,
        }
        for log in logs
    ]


@router.get("/replication/changes")
async def replication_changes(
    since_sequence: int = 0,
    limit: int = 100,
    user: User = Depends(get_current_user),  # noqa: B008
    session: AsyncSession = Depends(get_db),  # noqa: B008
) -> list[dict]:
    """Pull replication: fetch changes since a sequence number."""
    require_permission(user, "admin")
    repl = ReplicationEngine()
    changes = await repl.get_changes_since(session, since_sequence, limit=limit)
    return changes


@router.post("/replication/reset-sync")
async def replication_reset_sync(
    node_id: str,
    user: User = Depends(get_current_user),  # noqa: B008
    session: AsyncSession = Depends(get_db),  # noqa: B008
) -> dict:
    """Force full re-sync for a node."""
    require_permission(user, "admin")
    repl = ReplicationEngine()
    result = await repl.reset_sync(session, node_id)
    await session.commit()
    return result


@router.get("/replication/dead-letter")
async def list_dead_letter(
    user: User = Depends(get_current_user),  # noqa: B008
    session: AsyncSession = Depends(get_db),  # noqa: B008
) -> list[dict]:
    """List dead letter queue entries."""
    require_permission(user, "admin")
    from cryptodb.db.metadata import ReplicationDeadLetter
    result = await session.execute(
        select(ReplicationDeadLetter).order_by(ReplicationDeadLetter.created_at.desc())
    )
    rows = result.scalars().all()
    return [
        {
            "id": r.id,
            "record_id": r.record_id,
            "node_id": r.node_id,
            "sequence_number": r.sequence_number,
            "error_history": r.error_history,
            "created_at": r.created_at.isoformat(),
        }
        for r in rows
    ]


# ---------------------------------------------------------------------------
# Standby-side endpoints (called by primary)
# ---------------------------------------------------------------------------


@router.get("/replication/heartbeat", status_code=status.HTTP_204_NO_CONTENT)
async def replication_heartbeat() -> None:
    """Simple health endpoint for primary to ping."""
    return None


@router.post("/replication/push", response_model=ReplicationPushResponse)
async def replication_receive_push(
    payload: ReplicationPushPayload,
) -> ReplicationPushResponse:
    """Receive a replicated record from the primary node."""
    import base64
    import hashlib

    ciphertext = base64.b64decode(payload.ciphertext_b64)
    checksum_ok = hashlib.sha3_256(ciphertext).hexdigest() == payload.checksum
    if not checksum_ok:
        return ReplicationPushResponse(status="checksum_mismatch", checksum_ok=False)

    # Persist to local standby storage
    from cryptodb.storage.blob import BlobStore
    blob_store = BlobStore()
    await blob_store.write(payload.record_id, ciphertext)

    # TODO: persist metadata snapshot to local metadata DB if desired
    return ReplicationPushResponse(status="acked", checksum_ok=True)


@router.post("/replication/audit")
async def replication_receive_audit(
    payload: ReplicationAuditPayload,
) -> dict:
    """Receive an audit log entry from the primary node."""
    # TODO: persist metadata snapshot to local metadata DB if desired
    return {"status": "acked", "entry_number": payload.entry_number}


# ---------------------------------------------------------------------------
# Hardware token endpoints (FIDO2 + TPM)
# ---------------------------------------------------------------------------


@router.post("/auth/hardware/register-begin", response_model=HardwareRegisterBeginResponse)
async def hardware_register_begin(
    payload: HardwareRegisterBeginPayload,
    user: User = Depends(get_current_user),  # noqa: B008
    session: AsyncSession = Depends(get_db),  # noqa: B008
) -> HardwareRegisterBeginResponse:
    """Start FIDO2 hardware token registration."""
    from cryptodb.auth.hardware import HardwareTokenManager
    from cryptodb.auth.mfa import get_mfa_store

    mgr = HardwareTokenManager()
    if not mgr.fido2_available():
        raise HTTPException(status_code=501, detail="FIDO2 not available")

    existing = await mgr.get_credentials(session, user.id)
    registration_data, state = mgr.register_begin(user, existing)
    challenge_token = get_mfa_store().create(user.id, "fido2", state)
    return HardwareRegisterBeginResponse(
        public_credential_options=registration_data,
        challenge_token=challenge_token,
    )


@router.post("/auth/hardware/register-finish", response_model=HardwareRegisterFinishResponse)
async def hardware_register_finish(
    payload: HardwareRegisterFinishPayload,
    user: User = Depends(get_current_user),  # noqa: B008
    session: AsyncSession = Depends(get_db),  # noqa: B008
) -> HardwareRegisterFinishResponse:
    """Finish FIDO2 hardware token registration."""
    from cryptodb.auth.hardware import HardwareTokenManager
    from cryptodb.auth.mfa import get_mfa_store

    mgr = HardwareTokenManager()
    challenge = get_mfa_store().get(payload.challenge_token)
    if challenge is None or challenge.user_id != user.id:
        raise HTTPException(status_code=400, detail="Invalid or expired challenge token")

    try:
        credential = mgr.register_end(challenge.state, payload.client_response)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Registration verification failed: {exc}")

    await mgr.save_credential(session, user.id, credential)
    get_mfa_store().remove(payload.challenge_token)
    await session.commit()

    credential_id_b64 = base64.urlsafe_b64encode(credential.credential_id).decode().rstrip("=")
    return HardwareRegisterFinishResponse(credential_id=credential_id_b64, status="registered")


@router.post("/auth/hardware/authenticate-begin", response_model=HardwareAuthenticateBeginResponse)
async def hardware_authenticate_begin(
    payload: LoginPayload,
    session: AsyncSession = Depends(get_db),  # noqa: B008
) -> HardwareAuthenticateBeginResponse:
    """Start FIDO2 hardware token authentication (step 1 of MFA login)."""
    from cryptodb.auth.hardware import HardwareTokenManager
    from cryptodb.auth.mfa import get_mfa_store
    from cryptodb.auth.users import authenticate_user

    user = await authenticate_user(session, payload.username, payload.password)
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    mgr = HardwareTokenManager()
    if not mgr.fido2_available():
        raise HTTPException(status_code=501, detail="FIDO2 not available")

    credentials = await mgr.get_credentials(session, user.id)
    if not credentials:
        raise HTTPException(status_code=400, detail="No hardware credentials registered")

    auth_data, state = mgr.authenticate_begin(credentials)
    challenge_token = get_mfa_store().create(user.id, "fido2", state)
    return HardwareAuthenticateBeginResponse(
        public_request_options=auth_data,
        challenge_token=challenge_token,
    )


@router.post("/auth/hardware/authenticate-finish", response_model=LoginResponse)
async def hardware_authenticate_finish(
    payload: HardwareAuthenticateFinishPayload,
    session: AsyncSession = Depends(get_db),  # noqa: B008
) -> LoginResponse:
    """Finish FIDO2 hardware token authentication (step 2 of MFA login)."""
    import base64

    from cryptodb.auth.hardware import HardwareTokenManager
    from cryptodb.auth.mfa import get_mfa_store, issue_tokens
    from cryptodb.auth.session import create_session

    mgr = HardwareTokenManager()
    challenge = get_mfa_store().get(payload.challenge_token)
    if challenge is None:
        raise HTTPException(status_code=400, detail="Invalid or expired challenge token")

    result = await session.execute(
        select(User).where(User.id == challenge.user_id)
    )
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=400, detail="User not found")

    credentials = await mgr.get_credentials(session, user.id)
    try:
        verified_cred = mgr.authenticate_end(challenge.state, credentials, payload.client_response)
    except Exception as exc:
        raise HTTPException(status_code=401, detail=f"Authentication verification failed: {exc}")

    await mgr.update_sign_count(session, user.id, verified_cred)
    get_mfa_store().remove(payload.challenge_token)

    access, refresh = await create_session(session, user)
    await session.commit()
    return LoginResponse(access_token=access, refresh_token=refresh)


@router.post("/master-key/seal", response_model=SealMasterKeyResponse)
async def seal_master_key(
    payload: SealMasterKeyPayload,
    user: User = Depends(get_current_user),  # noqa: B008
) -> SealMasterKeyResponse:
    """Seal the master key using TPM (or software fallback). Admin only."""
    require_permission(user, "admin")
    from cryptodb.auth.hardware import HardwareTokenManager
    from cryptodb.crypto.keystore import MasterKeyStore

    mgr = HardwareTokenManager()
    ks = MasterKeyStore()
    kek = ks.load_master_key(payload.passphrase)
    sealed = mgr.tpm_seal(kek)
    method = "tpm" if mgr._tpm._esapi is not None else "software"
    return SealMasterKeyResponse(
        sealed_blob_b64=base64.b64encode(sealed).decode(),
        method=method,
    )


@router.post("/master-key/unseal")
async def unseal_master_key(
    payload: SealMasterKeyPayload,
    sealed_blob_b64: str,
    user: User = Depends(get_current_user),  # noqa: B008
    session: AsyncSession = Depends(get_db),  # noqa: B008
) -> dict:
    """Unseal the master key using TPM (or software fallback) and initialize engine. Admin only."""
    require_permission(user, "admin")
    from cryptodb.auth.hardware import HardwareTokenManager

    mgr = HardwareTokenManager()
    sealed = base64.b64decode(sealed_blob_b64)
    kek = mgr.tpm_unseal(sealed)
    chain = await CryptoDBEngine.load_chain(session)
    global _engine, _repl_engine
    _repl_engine = ReplicationEngine() if settings.replication_enabled else None
    _engine = CryptoDBEngine(kek, hash_chain=chain, replication_engine=_repl_engine)
    return {"status": "unsealed", "key_id": settings.master_key_id}

