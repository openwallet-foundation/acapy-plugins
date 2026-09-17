"""JWKS cache with TTL and refresh-on-kid-miss."""

import asyncio
import ipaddress
import socket
import time
from collections import OrderedDict
from urllib.parse import urlparse

import httpx
from joserfc.jwk import Key, KeySet

from core.utils.logging import get_logger

logger = get_logger(__name__)


class JWKSCache:
    """Cache JWKS documents with TTL and refresh-on-kid-miss.

    Two usage patterns:
      URI mode — ``get_jwks(uri, kid=...)`` fetches/caches by URI.
      Put mode — ``put(key, jwks, jwks_uri=...)`` pre-loads a keyset,
      ``get_key(key, kid)`` resolves a single key with refresh-on-miss.
    """

    def __init__(self, ttl: int = 300, max_size: int = 128):
        """TTL in seconds, max entries before LRU eviction."""
        self._cache: OrderedDict[str, tuple[float, KeySet | None, str | None]] = (
            OrderedDict()
        )
        self._ttl = ttl
        self._max_size = max_size

    @staticmethod
    def _find_key(key_set: KeySet, kid: str) -> Key | None:
        """Return key by kid, or None if not found."""
        try:
            return key_set.get_by_kid(kid)
        except Exception:
            return None

    @staticmethod
    async def _check_ssrf(uri: str) -> None:
        """Block URIs that resolve to non-globally-routable addresses."""
        parsed = urlparse(uri)
        if parsed.scheme not in ("https", "http"):
            raise ValueError(f"Unsupported scheme: {parsed.scheme}")
        hostname = parsed.hostname
        if not hostname:
            raise ValueError("Missing hostname")

        # IP literal
        try:
            addr = ipaddress.ip_address(hostname)
        except ValueError:
            addr = None

        if addr is not None:
            if not addr.is_global:
                raise ValueError(f"Blocked address: {hostname}")
            return

        # Hostname — resolve and check all addresses
        loop = asyncio.get_running_loop()
        infos = await loop.run_in_executor(
            None,
            lambda: socket.getaddrinfo(
                hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM
            ),
        )
        for info in infos:
            if not ipaddress.ip_address(info[4][0]).is_global:
                raise ValueError(f"Blocked address: {info[4][0]} (from {hostname})")

    @staticmethod
    async def _fetch(uri: str) -> KeySet | None:
        """Fetch JWKS from URI after SSRF validation. Returns None if empty."""
        await JWKSCache._check_ssrf(uri)
        async with httpx.AsyncClient(timeout=10) as client:
            data = (await client.get(uri)).raise_for_status().json()
        keys = data.get("keys") if isinstance(data, dict) else None
        return KeySet.import_key_set(data) if keys else None

    def _touch(self, key: str) -> None:
        """Move key to end and evict LRU if over capacity."""
        self._cache.move_to_end(key)
        while len(self._cache) > self._max_size:
            self._cache.popitem(last=False)

    # ── Put mode ───────────────────────────────────────────

    def put(self, key: str, jwks: dict | None, *, jwks_uri: str | None = None) -> None:
        """Store a JWKS document directly (e.g. loaded from DB)."""
        key_set = KeySet.import_key_set(jwks) if (jwks and jwks.get("keys")) else None
        self._cache[key] = (time.time(), key_set, jwks_uri)
        self._touch(key)

    def get_keyset(self, key: str) -> KeySet | None:
        """Return the full KeySet for a cache key, or None if not cached."""
        cached = self._cache.get(key)
        if not cached:
            return None
        self._touch(key)
        _, key_set, _ = cached
        return key_set

    def is_stale(self, key: str) -> bool:
        """Return True when the entry is absent or older than the TTL."""
        cached = self._cache.get(key)
        if not cached:
            return True
        return (time.time() - cached[0]) >= self._ttl

    async def get_key(self, key: str, kid: str) -> Key | None:
        """Return a single key by kid, refreshing from jwks_uri on miss."""
        cached = self._cache.get(key)
        if not cached:
            return None

        self._touch(key)
        _, key_set, refresh_uri = cached

        if key_set:
            found = self._find_key(key_set, kid)
            if found:
                return found

        if not refresh_uri:
            return None

        logger.info("kid %r miss for %s, refreshing", kid, key)
        try:
            key_set = await self._fetch(refresh_uri)
            self._cache[key] = (time.time(), key_set, refresh_uri)
            self._touch(key)
            return self._find_key(key_set, kid) if key_set else None
        except Exception:
            logger.warning("Failed to refresh JWKS from %s", refresh_uri, exc_info=True)
            return None

    # ── URI mode ───────────────────────────────────────────

    async def get_jwks(self, uri: str, *, kid: str | None = None) -> KeySet | None:
        """Return cached KeySet by URI, fetching/refreshing as needed."""
        now = time.time()
        cached = self._cache.get(uri)

        if cached:
            ts, key_set, _ = cached
            if now - ts < self._ttl:
                if key_set and (kid is None or self._find_key(key_set, kid)):
                    return key_set
                logger.info("kid %r miss for %s, refreshing", kid, uri)

        try:
            key_set = await self._fetch(uri)
            self._cache[uri] = (time.time(), key_set, uri)
            self._touch(uri)
            return key_set
        except Exception:
            logger.warning("Failed to fetch JWKS from %s", uri, exc_info=True)
            return cached[1] if cached else None

    def invalidate(self, key: str) -> None:
        """Remove a cached entry."""
        self._cache.pop(key, None)
