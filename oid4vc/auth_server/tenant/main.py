"""Tenant API."""

from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import Depends, FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import ORJSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from core.observability.observability import (
    RequestContextMiddleware,
    setup_structlog_json,
)
from core.utils.logging import get_logger
from tenant.config import settings

from .deps import get_db_session
from .routers.grants import router as grants_router
from .routers.introspect import router as introspect_router
from .routers.token import router as token_router
from .routers.well_known import router as well_known_router

logger = get_logger(__name__)

root_path = settings.APP_ROOT_PATH


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Startup/shutdown hooks."""
    setup_structlog_json()
    yield


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

app.include_router(well_known_router)
app.include_router(token_router)
app.include_router(grants_router)
app.include_router(introspect_router)


@app.get("/healthz")
async def health_check():
    """Simple tenant server health check."""
    return {"status": "ok"}


@app.get("/tenants/{uid}/healthz")
async def tenant_health_check(uid: str, db: AsyncSession = Depends(get_db_session)):
    """Tenant-scoped health check; DB connectivity is verified by dependency ping."""
    return {"status": "ok", "tenant": uid}


@app.exception_handler(Exception)
async def log_unhandled_exception(request: Request, ex: Exception):
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
        content={"status": "fail", "error": f"Internal Server Error: {ex}"},
    )
