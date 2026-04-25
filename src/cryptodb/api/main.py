"""FastAPI application factory."""

from contextlib import asynccontextmanager

from fastapi import FastAPI

from cryptodb.api.routes import router


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
    app.include_router(router, prefix="/api/v1")
    return app


app = create_app()
