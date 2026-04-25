"""FastAPI application factory."""

import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from cryptodb.api.routes import router
from cryptodb.config import settings


@asynccontextmanager
async def lifespan(app: FastAPI):  # noqa: ARG001
    """Application lifespan events."""
    yield


def create_app() -> FastAPI:
    app = FastAPI(
        title="CryptoDB",
        description="A cryptographic database with immutable audit ledger",
        version="0.1.0",
        lifespan=lifespan,
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

    app.include_router(router, prefix="/api/v1")

    @app.exception_handler(PermissionError)
    async def permission_error_handler(request: Request, exc: PermissionError) -> JSONResponse:  # noqa: ARG001
        return JSONResponse(
            status_code=403,
            content={"detail": str(exc)},
        )

    return app


app = create_app()
