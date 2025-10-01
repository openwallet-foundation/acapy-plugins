"""Logging helpers: unified `get_logger` with structlog or stdlib fallback."""

import os
import logging
from logging.handlers import RotatingFileHandler

try:
    import structlog  # type: ignore

    HAS_STRUCTLOG = True
except Exception:  # pragma: no cover - optional dependency
    structlog = None  # type: ignore
    HAS_STRUCTLOG = False


def get_logger(
    name: str,
    log_file: str = "logs/app.log",
    level: int = logging.INFO,
    max_bytes: int = 5 * 1024 * 1024,
    backup_count: int = 3,
    enable_console: bool = True,
    enable_file: bool = False,
):
    """Return a structlog logger if available, else a configured stdlib logger."""

    if HAS_STRUCTLOG:
        # Defer import use to avoid type issues when structlog missing
        return structlog.get_logger(name)  # type: ignore[no-any-return]

    # Fallback to stdlib logger
    return create_logger(
        name=name,
        log_file=log_file,
        level=level,
        max_bytes=max_bytes,
        backup_count=backup_count,
        enable_console=enable_console,
        enable_file=enable_file,
    )


def create_logger(
    name: str,
    log_file: str,
    level: int,
    max_bytes: int,
    backup_count: int,
    enable_console: bool,
    enable_file: bool,
) -> logging.Logger:
    """Create a logger instance."""

    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.propagate = False

    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    if enable_console and not any(
        isinstance(h, logging.StreamHandler) for h in logger.handlers
    ):
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    if enable_file and not any(
        isinstance(h, RotatingFileHandler) for h in logger.handlers
    ):
        if log_dir := os.path.dirname(log_file):
            os.makedirs(log_dir, exist_ok=True)
        handler = RotatingFileHandler(
            log_file, maxBytes=max_bytes, backupCount=backup_count, encoding="utf-8"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger
