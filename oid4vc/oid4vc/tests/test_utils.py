"""Tests for oid4vc utils."""

import pytest

from oid4vc.utils import get_auth_header, get_tenant_subpath


def test_get_tenant_subpath(profile):
    profile.context.settings.set_value("multitenant.enabled", True)
    assert get_tenant_subpath(profile) == "/tenants/538451fa-11ab-41de-b6e3-7ae3df7356d6"


@pytest.mark.asyncio
async def test_get_auth_header_client_secret_basic(monkeypatch, config, profile):
    auth_server = {
        "auth_type": "client_secret_basic",
        "client_credentials": {"client_id": "client_id", "client_secret": "secret"},
    }
    header = await get_auth_header(profile, auth_server, "issuer", "audience")
    assert header.startswith("Basic ")


@pytest.mark.asyncio
async def test_get_auth_header_missing_client(monkeypatch, config, profile):
    auth_server = {"auth_type": "client_secret_basic"}  # missing client_credentials
    with pytest.raises((ValueError, KeyError)):
        await get_auth_header(profile, auth_server, "issuer", "audience")
