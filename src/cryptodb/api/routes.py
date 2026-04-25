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

router = APIRouter()

_engine: CryptoDBEngine | None = None


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
    global _engine
    _engine = CryptoDBEngine(kek, hash_chain=chain)
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
    global _engine
    _engine = CryptoDBEngine(kek, hash_chain=chain)
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
