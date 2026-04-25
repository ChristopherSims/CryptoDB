"""FastAPI routes for CryptoDB."""

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from cryptodb.api.dependencies import get_current_user, get_db
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


@router.post("/records", response_model=PutResponse)
async def create_record(
    payload: PutPayload,
    user: User = Depends(get_current_user),  # noqa: B008
    session: AsyncSession = Depends(get_db),  # noqa: B008
) -> PutResponse:
    import base64
    engine = get_engine()
    plaintext = base64.b64decode(payload.data_b64)
    record = await engine.put(
        session, user, plaintext,
        cipher_name=payload.cipher_name,
        compress_algo=payload.compress,
        searchable_fields=payload.searchable,
        he_fields=payload.he_fields,
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


@router.get("/health")
async def health_check() -> dict:
    return {"status": "ok", "engine_ready": _engine is not None}


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
    # TODO: persist to local audit ledger if desired
    return {"status": "acked", "entry_number": payload.entry_number}

