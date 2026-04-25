"""FastAPI application factory."""

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

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

    @app.exception_handler(PermissionError)
    async def permission_error_handler(request: Request, exc: PermissionError) -> JSONResponse:  # noqa: ARG001
        return JSONResponse(
            status_code=403,
            content={"detail": str(exc)},
        )

    return app


app = create_app()
