"""Per-request context registry for OAuth2Request objects."""

from types import SimpleNamespace
from typing import Any
from weakref import WeakKeyDictionary

_CTX: "WeakKeyDictionary[object, SimpleNamespace]" = WeakKeyDictionary()


def set_context(req: object, *, db: Any = None, uid: str | None = None) -> None:
    """Attach context to a request via a weak map."""
    _CTX[req] = SimpleNamespace(db=db, uid=uid)


def get_context(req: object) -> SimpleNamespace:
    """Return previously attached context for the request (or empty)."""
    return _CTX.get(req, SimpleNamespace())


def update_context(req: object, **kwargs: Any) -> None:
    """Merge additional attributes into the stored context."""
    ns = _CTX.get(req)
    if ns is None:
        ns = SimpleNamespace()
    for k, v in kwargs.items():
        setattr(ns, k, v)
    _CTX[req] = ns
