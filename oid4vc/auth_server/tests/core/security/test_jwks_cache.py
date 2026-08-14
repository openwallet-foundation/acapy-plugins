from unittest.mock import AsyncMock, patch

import httpx
from joserfc.jwk import ECKey, KeySet

from core.security.jwks_cache import JWKSCache

# Generate real EC keys so KeySet.import_key_set works
_raw_k1 = ECKey.generate_key("P-256").as_dict(private=False, kid="k1")
_raw_k2 = ECKey.generate_key("P-256").as_dict(private=False, kid="k2")

JWKS_A = {"keys": [_raw_k1]}
JWKS_B = {"keys": [_raw_k1, _raw_k2]}
KS_A = KeySet.import_key_set(JWKS_A)
KS_B = KeySet.import_key_set(JWKS_B)


# ── URI mode (get_jwks) ──────────────────────────────────


class TestJWKSCacheGetJwks:
    async def test_returns_fetched_jwks(self):
        cache = JWKSCache(ttl=300)
        with patch.object(cache, "_fetch", new=AsyncMock(return_value=KS_A)):
            result = await cache.get_jwks("https://example.com/jwks")
        assert len(result.keys) == 1
        assert result.keys[0].kid == "k1"

    async def test_returns_cached_within_ttl(self):
        cache = JWKSCache(ttl=300)
        fetch = AsyncMock(return_value=KS_A)
        with patch.object(cache, "_fetch", new=fetch):
            await cache.get_jwks("https://example.com/jwks")
            result = await cache.get_jwks("https://example.com/jwks")
        assert len(result.keys) == 1
        assert fetch.call_count == 1

    async def test_refreshes_after_ttl_expires(self):
        cache = JWKSCache(ttl=10)
        fetch = AsyncMock(return_value=KS_A)
        with patch.object(cache, "_fetch", new=fetch):
            await cache.get_jwks("https://example.com/jwks")
            ts, ks, uri = cache._cache["https://example.com/jwks"]
            cache._cache["https://example.com/jwks"] = (ts - 20, ks, uri)
            await cache.get_jwks("https://example.com/jwks")
        assert fetch.call_count == 2

    async def test_refreshes_on_kid_miss(self):
        cache = JWKSCache(ttl=300)
        fetch = AsyncMock(side_effect=[KS_A, KS_B])
        with patch.object(cache, "_fetch", new=fetch):
            await cache.get_jwks("https://example.com/jwks")
            result = await cache.get_jwks(
                "https://example.com/jwks",
                kid="k2",
            )
        assert len(result.keys) == 2
        assert fetch.call_count == 2

    async def test_no_refresh_when_kid_found(self):
        cache = JWKSCache(ttl=300)
        fetch = AsyncMock(return_value=KS_A)
        with patch.object(cache, "_fetch", new=fetch):
            await cache.get_jwks("https://example.com/jwks")
            result = await cache.get_jwks(
                "https://example.com/jwks",
                kid="k1",
            )
        assert len(result.keys) == 1
        assert fetch.call_count == 1

    async def test_returns_stale_cache_on_fetch_failure(self):
        cache = JWKSCache(ttl=10)
        with patch.object(cache, "_fetch", new=AsyncMock(return_value=KS_A)):
            await cache.get_jwks("https://example.com/jwks")
        ts, ks, uri = cache._cache["https://example.com/jwks"]
        cache._cache["https://example.com/jwks"] = (ts - 20, ks, uri)
        with patch.object(
            cache,
            "_fetch",
            new=AsyncMock(side_effect=httpx.HTTPError("timeout")),
        ):
            result = await cache.get_jwks("https://example.com/jwks")
        assert len(result.keys) == 1

    async def test_returns_none_on_fetch_failure_no_stale(self):
        cache = JWKSCache(ttl=300)
        with patch.object(
            cache,
            "_fetch",
            new=AsyncMock(side_effect=httpx.HTTPError("fail")),
        ):
            assert await cache.get_jwks("https://example.com/jwks") is None

    async def test_separate_uris_cached_independently(self):
        cache = JWKSCache(ttl=300)
        ks_other = KeySet.import_key_set({"keys": [_raw_k2]})
        fetch = AsyncMock(side_effect=[KS_A, ks_other])
        with patch.object(cache, "_fetch", new=fetch):
            r1 = await cache.get_jwks("https://a.example.com/jwks")
            r2 = await cache.get_jwks("https://b.example.com/jwks")
        assert r1.keys[0].kid == "k1"
        assert r2.keys[0].kid == "k2"
        assert fetch.call_count == 2


class TestJWKSCacheInvalidate:
    async def test_invalidate_forces_refetch(self):
        cache = JWKSCache(ttl=300)
        fetch = AsyncMock(return_value=KS_A)
        with patch.object(cache, "_fetch", new=fetch):
            await cache.get_jwks("https://example.com/jwks")
            cache.invalidate("https://example.com/jwks")
            await cache.get_jwks("https://example.com/jwks")
        assert fetch.call_count == 2

    async def test_invalidate_nonexistent_is_noop(self):
        cache = JWKSCache(ttl=300)
        cache.invalidate("https://nonexistent.example.com/jwks")


# ── Put mode (put + get_key) ─────────────────────────────


class TestJWKSCachePut:
    def test_put_stores_entry(self):
        cache = JWKSCache(ttl=300)
        cache.put("iss1", JWKS_A)
        assert "iss1" in cache._cache

    def test_put_with_jwks_uri(self):
        cache = JWKSCache(ttl=300)
        cache.put("iss1", JWKS_A, jwks_uri="https://p.example/jwks")
        _, _, uri = cache._cache["iss1"]
        assert uri == "https://p.example/jwks"

    def test_put_overwrites_existing(self):
        cache = JWKSCache(ttl=300)
        cache.put("iss1", JWKS_A)
        cache.put("iss1", JWKS_B)
        _, ks, _ = cache._cache["iss1"]
        assert len(ks.keys) == 2


class TestJWKSCacheGetKey:
    async def test_returns_key_from_put_entry(self):
        cache = JWKSCache(ttl=300)
        cache.put("iss1", JWKS_A)
        result = await cache.get_key("iss1", "k1")
        assert result is not None
        assert result.kid == "k1"

    async def test_returns_none_for_unknown_iss(self):
        cache = JWKSCache(ttl=300)
        assert await cache.get_key("unknown", "k1") is None

    async def test_inline_kid_miss_returns_none(self):
        cache = JWKSCache(ttl=300)
        cache.put("iss1", JWKS_A)
        assert await cache.get_key("iss1", "k999") is None

    async def test_jwks_uri_refreshes_on_kid_miss(self):
        cache = JWKSCache(ttl=300)
        cache.put("iss1", JWKS_A, jwks_uri="https://p.example/jwks")
        with patch.object(cache, "_fetch", new=AsyncMock(return_value=KS_B)):
            result = await cache.get_key("iss1", "k2")
        assert result is not None
        assert result.kid == "k2"

    async def test_jwks_uri_refresh_still_missing(self):
        cache = JWKSCache(ttl=300)
        cache.put("iss1", JWKS_A, jwks_uri="https://p.example/jwks")
        with patch.object(cache, "_fetch", new=AsyncMock(return_value=KS_A)):
            assert await cache.get_key("iss1", "k999") is None

    async def test_jwks_uri_refresh_failure(self):
        cache = JWKSCache(ttl=300)
        cache.put("iss1", JWKS_A, jwks_uri="https://p.example/jwks")
        with patch.object(
            cache,
            "_fetch",
            new=AsyncMock(side_effect=httpx.HTTPError("fail")),
        ):
            assert await cache.get_key("iss1", "k999") is None

    async def test_invalidate_then_get_key(self):
        cache = JWKSCache(ttl=300)
        cache.put("iss1", JWKS_A)
        cache.invalidate("iss1")
        assert await cache.get_key("iss1", "k1") is None
