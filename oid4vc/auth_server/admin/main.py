"""Admin API for tenant management."""

from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import ORJSONResponse
from sqlalchemy import text

from admin.config import settings
from admin.deps import db_manager
from admin.routers import internal, migrations, tenants
from core.observability.observability import (
    RequestContextMiddleware,
    setup_structlog_json,
)
from core.utils.logging import get_logger

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Lifespan event handler."""
    # Startup logic
    setup_structlog_json()
    db_manager.init(settings.DB_URL)
    # Warn if encryption keys are not configured; secrets will be stored in plaintext
    try:
        active_ver = str(getattr(settings, "KEY_ENC_VERSION", 1))
        secrets_map = getattr(settings, "KEY_ENC_SECRETS", {}) or {}
        if not secrets_map.get(active_ver):
            logger.warning(
                "KEY_ENC_SECRETS missing active version v%s; "
                "secrets may be stored unencrypted",
                active_ver,
            )
    except Exception:
        # Non-fatal; continue startup
        logger.warning("Failed to validate KEY_ENC_SECRETS configuration")
    yield
    # Shutdown logic
    await db_manager.close()


root_path = settings.APP_ROOT_PATH
app = FastAPI(
    title=settings.APP_TITLE,
    version=settings.APP_VERSION,
    openapi_url=f"{root_path}{settings.OPENAPI_URL}",
    default_response_class=ORJSONResponse,
    lifespan=lifespan,
    root_path=root_path,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ALLOW_ORIGINS,
    allow_methods=settings.CORS_ALLOW_METHODS,
    allow_headers=settings.CORS_ALLOW_HEADERS,
    allow_credentials=settings.CORS_ALLOW_CREDENTIALS,
)
app.add_middleware(RequestContextMiddleware)

app.include_router(tenants.router, prefix="/admin", tags=["tenants"])
app.include_router(migrations.router, prefix="/admin", tags=["migrations"])
app.include_router(internal.router, prefix="/internal", tags=["internal"])


@app.get("/healthz")
async def health_check():
    """Simple health check."""
    try:
        async with db_manager.session() as session:
            await session.execute(text("SELECT 1"))
        return ORJSONResponse(content={"status": "ok"}, status_code=status.HTTP_200_OK)
    except Exception as ex:
        error_message = f"database_unavailable: {ex}"
        logger.error(f"Health check failed: {error_message}")
        return ORJSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"status": "fail", "error": error_message},
        )


@app.exception_handler(Exception)
async def log_unhandled_exception(request: Request, exc: Exception):
    """Log unhandled exceptions with request context."""
    logger.exception(
        "unhandled_exception",
        extra={
            "method": f"{request.method}",
            "path": f"{request.url.path}",
            "path_params": f"{dict(request.path_params)}",
        },
    )
    return ORJSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal Server Error"},
    )
