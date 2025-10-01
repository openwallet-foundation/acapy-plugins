"""orjson utils."""

from typing import Any

import orjson

from core.utils.logging import get_logger

logger = get_logger(__name__)


def safe_json_loads(data: Any) -> dict:
    """Safe JSON loads."""
    try:
        return orjson.loads(data)
    except Exception as ex:
        logger.exception(f"Failed to load JSON: {ex}")
        return {}


def safe_json_dumps(data: Any, indent: bool = False) -> str:
    """Safe JSON dumps."""
    try:
        option = orjson.OPT_INDENT_2 if indent else None
        return orjson.dumps(data, option=option).decode("utf-8")
    except Exception as ex:
        logger.exception(f"Failed to dump JSON: {ex}")
        return ""
