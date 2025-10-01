"""Schemas for migrations."""

from enum import Enum
from pydantic import BaseModel


class MigrationAction(str, Enum):
    """Enum for migration actions."""

    upgrade = "upgrade"
    downgrade = "downgrade"


class MigrationRequest(BaseModel):
    """Migration request payload."""

    action: MigrationAction
    rev: str | None = None
