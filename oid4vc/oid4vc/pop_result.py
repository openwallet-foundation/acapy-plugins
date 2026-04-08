"""PopResult dataclass."""

from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional


@dataclass
class PopResult:
    """Result from proof of posession."""

    headers: Mapping[str, Any]
    payload: Mapping[str, Any]
    verified: bool
    holder_kid: Optional[str]
    holder_jwk: Optional[Dict[str, Any]]
    holder_x5c: Optional[List[str]] = None
