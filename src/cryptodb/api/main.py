"""FastAPI application factory."""

import uuid
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from cryptodb.api.routes import router
from cryptodb.config import settings
from cryptodb.db.connection import _engine, reset_engine
from cryptodb.exceptions import (
    AuthenticationError,
    AuthorizationError,
    ConfigurationError,
    CryptoDBException,
    IntegrityError,
    KeyManagementError,
    RecordNotFoundError,
    ReplicationError,
    ValidationError,
)
from cryptodb.logging_config import setup_logging


@asynccontextmanager
async def lifespan(app: FastAPI):  # noqa: ARG001
    """Application lifespan events."""
    setup_logging(level=settings.log_level)
    logger = structlog.get_logger()
    logger.info("application_starting")
    yield
    logger.info("application_shutting_down")
    if _engine is not None:
        await _engine.dispose()
        reset_engine()


def _error_response(exc: CryptoDBException) -> JSONResponse:
    return JSONResponse(
        status_code=exc.http_status,
        content={
            "error": exc.message,
            "code": exc.error_code,
            "detail": exc.detail,
        },
    )


def create_app() -> FastAPI:
    app = FastAPI(
        title="CryptoDB",
        description="A cryptographic database with immutable audit ledger",
        version="0.1.0",
        lifespan=lifespan,
        openapi_tags=[
            {"name": "Auth", "description": "Authentication and session management"},
            {"name": "Records", "description": "Encrypted record storage and retrieval"},
            {"name": "Audit", "description": "Immutable audit ledger"},
            {"name": "Admin", "description": "Administrative and maintenance operations"},
            {"name": "Replication", "description": "Multi-node replication"},
            {"name": "HE", "description": "Homomorphic encryption operations"},
        ],
    )

    # CORS
    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    # Request ID middleware
    @app.middleware("http")
    async def request_id_middleware(request: Request, call_next):
        request_id = request.headers.get("x-request-id")
        if not request_id:
            request_id = str(uuid.uuid4())
        request.state.request_id = request_id
        response = await call_next(request)
        response.headers["x-request-id"] = request_id
        return response

    # Add logging context middleware
    @app.middleware("http")
    async def logging_context_middleware(request: Request, call_next):
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(
            request_id=getattr(request.state, "request_id", ""),
            path=request.url.path,
            method=request.method,
        )
        response = await call_next(request)
        return response

    app.include_router(router, prefix="/api/v1")

    # ------------------------------------------------------------------
    # Exception handlers
    # ------------------------------------------------------------------

    @app.exception_handler(PermissionError)
    async def permission_error_handler(request: Request, exc: PermissionError) -> JSONResponse:  # noqa: ARG001
        return JSONResponse(
            status_code=403,
            content={"error": str(exc), "code": "AUTHORIZATION_ERROR", "detail": {}},
        )

    @app.exception_handler(CryptoDBException)
    async def cryptodb_exception_handler(request: Request, exc: CryptoDBException) -> JSONResponse:  # noqa: ARG001
        return _error_response(exc)

    @app.exception_handler(AuthenticationError)
    async def auth_error_handler(request: Request, exc: AuthenticationError) -> JSONResponse:  # noqa: ARG001
        return _error_response(exc)

    @app.exception_handler(AuthorizationError)
    async def authorization_error_handler(request: Request, exc: AuthorizationError) -> JSONResponse:  # noqa: ARG001
        return _error_response(exc)

    @app.exception_handler(RecordNotFoundError)
    async def not_found_error_handler(request: Request, exc: RecordNotFoundError) -> JSONResponse:  # noqa: ARG001
        return _error_response(exc)

    @app.exception_handler(IntegrityError)
    async def integrity_error_handler(request: Request, exc: IntegrityError) -> JSONResponse:  # noqa: ARG001
        return _error_response(exc)

    @app.exception_handler(KeyManagementError)
    async def key_error_handler(request: Request, exc: KeyManagementError) -> JSONResponse:  # noqa: ARG001
        return _error_response(exc)

    @app.exception_handler(ReplicationError)
    async def replication_error_handler(request: Request, exc: ReplicationError) -> JSONResponse:  # noqa: ARG001
        return _error_response(exc)

    @app.exception_handler(ConfigurationError)
    async def config_error_handler(request: Request, exc: ConfigurationError) -> JSONResponse:  # noqa: ARG001
        return _error_response(exc)

    @app.exception_handler(ValidationError)
    async def validation_error_handler(request: Request, exc: ValidationError) -> JSONResponse:  # noqa: ARG001
        return _error_response(exc)

    return app


app = create_app()
