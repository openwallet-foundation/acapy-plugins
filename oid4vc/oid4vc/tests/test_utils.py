"""Tests for oid4vc utils."""

import pytest

from oid4vc.utils import get_auth_header, get_tenant_subpath


def test_get_tenant_subpath(profile):
    profile.context.settings.set_value("multitenant.enabled", True)
    assert get_tenant_subpath(profile) == "/tenants/538451fa-11ab-41de-b6e3-7ae3df7356d6"


@pytest.mark.asyncio
async def test_get_auth_header_client_secret_basic(monkeypatch, config, profile):
    header = await get_auth_header(profile, config, "issuer", "audience")
    assert header.startswith("Basic ")


@pytest.mark.asyncio
async def test_get_auth_header_missing_client(monkeypatch, config, profile):
    config.auth_server_client = None
    with pytest.raises(ValueError):
        await get_auth_header(profile, config, "issuer", "audience")
