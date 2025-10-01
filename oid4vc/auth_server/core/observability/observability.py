"""Observability helpers: structlog JSON + request context."""

import logging
import time
import typing
import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

try:
    import structlog
    from structlog.contextvars import bind_contextvars, clear_contextvars
    from structlog.contextvars import get_contextvars as _get_ctxvars
    from structlog.processors import TimeStamper
    from structlog.stdlib import ProcessorFormatter, ExtraAdder

    HAS_STRUCTLOG = True
except Exception:  # pragma: no cover - optional dependency
    structlog = None  # type: ignore
    bind_contextvars = clear_contextvars = None  # type: ignore
    _get_ctxvars = None  # type: ignore
    ProcessorFormatter = None  # type: ignore
    TimeStamper = None  # type: ignore
    HAS_STRUCTLOG = False


def setup_structlog_json() -> bool:
    """Configure structlog JSON output; return True if enabled."""
    if not HAS_STRUCTLOG:  # pragma: no cover - optional path
        logging.getLogger(__name__).warning(
            "structlog not installed; falling back to stdlib logging"
        )
        return False

    # Configure stdlib root logger to use ProcessorFormatter
    shared_processors = [
        structlog.processors.add_log_level,
        TimeStamper(fmt="iso", utc=True),
        ExtraAdder(),  # include stdlib `extra` dict fields
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
    ]

    formatter = ProcessorFormatter(
        processor=structlog.processors.JSONRenderer(),
        foreign_pre_chain=shared_processors,
    )

    handler = logging.StreamHandler()
    handler.setFormatter(formatter)

    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(logging.INFO)

    # Configure structlog to route through stdlib
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.stdlib.filter_by_level,
            *shared_processors,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )
    return True


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Bind request_id/method/path to logs and set X-Request-ID."""

    def __init__(self, app, header_name: str = "X-Request-ID") -> None:
        """Constructor."""
        super().__init__(app)
        self.header_name = header_name
        self._logger = logging.getLogger(__name__)

    async def dispatch(
        self,
        request: Request,
        call_next: typing.Callable[[Request], typing.Awaitable[Response]],
    ):
        """Bind request_id to logs and set X-Request-ID header."""
        request_id = request.headers.get(self.header_name)
        if not request_id:
            request_id = str(uuid.uuid4())

        if HAS_STRUCTLOG and bind_contextvars is not None:
            bind_contextvars(
                request_id=request_id,
                method=request.method,
                path=request.url.path,
            )
        start = time.perf_counter()
        try:
            self._logger.info(
                "http.request.start",
                extra={
                    "request_id": request_id,
                    "method": request.method,
                    "path": request.url.path,
                    "client_host": getattr(request.client, "host", None),
                },
            )
            response = await call_next(request)
        finally:
            if HAS_STRUCTLOG and clear_contextvars is not None:
                clear_contextvars()

        duration_ms = int((time.perf_counter() - start) * 1000)
        try:
            client_id = getattr(request.state, "client_id", None)
            self._logger.info(
                "http.request.end",
                extra={
                    "request_id": request_id,
                    "method": request.method,
                    "path": request.url.path,
                    "status_code": getattr(response, "status_code", None),
                    "duration_ms": duration_ms,
                    "client_id": client_id,
                },
            )
        except Exception:
            # Logging failures should not affect response delivery
            pass

        response.headers[self.header_name] = request_id
        return response


def current_request_id(default: str | None = None) -> str | None:
    """Return bound request_id or default if missing."""
    if HAS_STRUCTLOG and _get_ctxvars is not None:  # pragma: no branch
        try:
            ctx = _get_ctxvars()
            rid = ctx.get("request_id") if isinstance(ctx, dict) else None
            return rid or default
        except Exception:
            return default
    return default
