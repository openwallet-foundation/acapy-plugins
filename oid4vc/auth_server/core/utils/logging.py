"""Structlog wrapper."""

import structlog


def get_logger(name: str):
    """Bound logger."""
    return structlog.get_logger(name)
