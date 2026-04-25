"""FastAPI routes for CryptoDB."""

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from cryptodb.api.dependencies import get_current_user, get_db
from cryptodb.auth.users import authenticate_user, create_user
from cryptodb.auth.session import create_session
from cryptodb.config import settings
from cryptodb.crypto.keystore import MasterKeyStore
from cryptodb.db.connection import init_db
from cryptodb.db.metadata import User
from cryptodb.engine import CryptoDBEngine

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


class PutResponse(BaseModel):
    record_id: str
    size_bytes: int


class GetResponse(BaseModel):
    data_b64: str
    record_id: str


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
    session: AsyncSession = Depends(get_db),  # noqa: B008
) -> dict:
    ks = MasterKeyStore()
    kek = ks.create_master_key(passphrase)
    chain = await CryptoDBEngine.load_chain(session)
    global _engine
    _engine = CryptoDBEngine(kek, hash_chain=chain)
    return {"status": "created", "key_id": settings.master_key_id}


@router.post("/master-key/unlock")
async def unlock_master_key(
    passphrase: str,
    session: AsyncSession = Depends(get_db),  # noqa: B008
) -> dict:
    ks = MasterKeyStore()
    kek = ks.load_master_key(passphrase)
    chain = await CryptoDBEngine.load_chain(session)
    global _engine
    _engine = CryptoDBEngine(kek, hash_chain=chain)
    return {"status": "unlocked", "key_id": settings.master_key_id}
