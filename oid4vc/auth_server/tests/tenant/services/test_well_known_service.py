from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from core.consts import SUPPORTED_SIGNING_ALGS
from tenant.services.well_known_service import build_oauth_auth_server


@pytest.mark.asyncio
async def test_security_features_are_not_advertised_when_disabled(monkeypatch):
    monkeypatch.setattr("tenant.services.well_known_service.get_tenant_ctx", AsyncMock())
    monkeypatch.setattr(
        "tenant.services.well_known_service.settings.ATTESTATION_ENABLED", False
    )

    doc = await build_oauth_auth_server(
        "tenant-1", SimpleNamespace(client=SimpleNamespace(host="203.0.113.1"))
    )

    assert doc["token_endpoint_auth_methods_supported"] == ["none"]
    assert "client_attestation_signing_alg_values_supported" not in doc
    assert "client_attestation_pop_signing_alg_values_supported" not in doc


@pytest.mark.asyncio
async def test_security_features_are_advertised_when_enabled(monkeypatch):
    monkeypatch.setattr("tenant.services.well_known_service.get_tenant_ctx", AsyncMock())
    monkeypatch.setattr(
        "tenant.services.well_known_service.settings.ATTESTATION_ENABLED", True
    )
    monkeypatch.setattr(
        "tenant.services.well_known_service.settings.ATTESTATION_REQUIRED", False
    )

    doc = await build_oauth_auth_server(
        "tenant-1", SimpleNamespace(client=SimpleNamespace(host="203.0.113.1"))
    )

    assert doc["token_endpoint_auth_methods_supported"] == [
        "none",
        "attest_jwt_client_auth",
    ]
    assert doc["client_attestation_signing_alg_values_supported"] == list(
        SUPPORTED_SIGNING_ALGS
    )
    assert doc["client_attestation_pop_signing_alg_values_supported"] == list(
        SUPPORTED_SIGNING_ALGS
    )


@pytest.mark.asyncio
async def test_required_attestation_does_not_advertise_none(monkeypatch):
    monkeypatch.setattr("tenant.services.well_known_service.get_tenant_ctx", AsyncMock())
    monkeypatch.setattr(
        "tenant.services.well_known_service.settings.ATTESTATION_ENABLED", True
    )
    monkeypatch.setattr(
        "tenant.services.well_known_service.settings.ATTESTATION_REQUIRED", True
    )

    doc = await build_oauth_auth_server(
        "tenant-1", SimpleNamespace(client=SimpleNamespace(host="203.0.113.1"))
    )

    assert doc["token_endpoint_auth_methods_supported"] == ["attest_jwt_client_auth"]
    assert doc["pre-authorized_grant_anonymous_access_supported"] is False
