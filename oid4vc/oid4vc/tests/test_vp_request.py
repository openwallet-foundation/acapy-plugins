"""Tests for Diff-2: wallet.id used without gating on multitenant.enabled."""

import json
from typing import cast
from unittest.mock import AsyncMock, MagicMock

import pytest
from acapy_agent.storage.error import StorageNotFoundError
from aiohttp import web

from oid4vc.routes.vp_request import create_oid4vp_request


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def vp_request_factory(context):
    """Factory producing a minimal DummyRequest for create_oid4vp_request."""

    class DummyRequest:
        def __init__(self, body=None):
            self._body = body or {
                "pres_def_id": "pres-def-001",
                "vp_formats": {"jwt_vp_json": {"alg": ["ES256"]}},
            }

        async def json(self):
            return self._body

        def __getitem__(self, key):
            if key == "context":
                return context
            raise KeyError(key)

    return DummyRequest


def _make_mock_session(storage_raises=True):
    """Return an async-context-manager-compatible mock session."""
    mock_storage = MagicMock()
    if storage_raises:
        mock_storage.get_record = AsyncMock(
            side_effect=StorageNotFoundError("no x509 record")
        )
    else:
        mock_storage.get_record = AsyncMock(
            return_value=MagicMock(value=json.dumps({"client_id": "example.com"}))
        )
    mock_storage.add_record = AsyncMock()

    session = MagicMock()
    session.inject = MagicMock(return_value=mock_storage)
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=False)
    return session


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestWalletIdWithoutMultitenantEnabled:
    """Diff-2: wallet.id must appear in request_uri even when multitenant.enabled
    is absent from sub-wallet profile settings (single-wallet-askar mode)."""

    @pytest.mark.asyncio
    async def test_request_uri_includes_tenant_path(
        self, context, vp_request_factory, monkeypatch
    ):
        """The request_uri must contain /tenant/{wallet_id}/ when wallet.id is set.

        The conftest settings include wallet.id but NOT multitenant.enabled.
        The old guard ``settings.get('multitenant.enabled')`` was always falsy
        in single-wallet-askar mode, so the tenant path was silently omitted.
        The fix reads wallet.id directly.
        """
        wallet_id = context.profile.settings["wallet.id"]
        assert context.profile.settings.get("multitenant.enabled") is None, (
            "Pre-condition: multitenant.enabled must be absent for this regression test"
        )
        assert wallet_id, "Pre-condition: wallet.id must be present in test settings"

        mock_jwk = MagicMock()
        mock_jwk.did = "did:jwk:abc123"

        mock_req = MagicMock()
        mock_req._id = "req-id-001"
        mock_req.serialize = MagicMock(return_value={"request_id": "req-id-001"})
        mock_req.save = AsyncMock()

        mock_pres = MagicMock()
        mock_pres.serialize = MagicMock(return_value={"pres_id": "pres-id-001"})
        mock_pres.save = AsyncMock()

        monkeypatch.setattr(
            "oid4vc.routes.vp_request.retrieve_or_create_did_jwk",
            AsyncMock(return_value=mock_jwk),
        )
        monkeypatch.setattr(
            "oid4vc.routes.vp_request.OID4VPRequest",
            MagicMock(return_value=mock_req),
        )
        monkeypatch.setattr(
            "oid4vc.routes.vp_request.OID4VPPresentation",
            MagicMock(return_value=mock_pres),
        )

        session = _make_mock_session(storage_raises=True)
        monkeypatch.setattr(context, "session", MagicMock(return_value=session))

        mock_config = MagicMock()
        mock_config.endpoint = "http://localhost:8020"
        mock_config.oid4vp_endpoint = None
        monkeypatch.setattr(
            "oid4vc.routes.vp_request.Config.from_settings",
            MagicMock(return_value=mock_config),
        )

        request = vp_request_factory()
        response = await create_oid4vp_request(cast(web.Request, request))

        assert response.status == 200
        body = json.loads(response.body)
        request_uri = body["request_uri"]

        assert f"/tenant/{wallet_id}/" in request_uri, (
            f"request_uri must contain /tenant/{{wallet_id}}/ but got: {request_uri!r}. "
            "Regression: without the fix, multitenant.enabled is absent in "
            "single-wallet-askar sub-wallet settings so the tenant path was omitted."
        )

    @pytest.mark.asyncio
    async def test_no_tenant_path_when_wallet_id_absent(
        self, context, vp_request_factory, monkeypatch
    ):
        """When wallet.id is not set (root / single-tenant deployment), subpath is
        empty and request_uri must NOT contain a /tenant/ segment."""
        # Temporarily remove wallet.id
        original = context.profile.settings.get("wallet.id")
        context.profile.settings["wallet.id"] = None

        try:
            mock_jwk = MagicMock()
            mock_jwk.did = "did:jwk:abc123"

            mock_req = MagicMock()
            mock_req._id = "req-id-002"
            mock_req.serialize = MagicMock(return_value={"request_id": "req-id-002"})
            mock_req.save = AsyncMock()

            mock_pres = MagicMock()
            mock_pres.serialize = MagicMock(return_value={"pres_id": "pres-id-002"})
            mock_pres.save = AsyncMock()

            monkeypatch.setattr(
                "oid4vc.routes.vp_request.retrieve_or_create_did_jwk",
                AsyncMock(return_value=mock_jwk),
            )
            monkeypatch.setattr(
                "oid4vc.routes.vp_request.OID4VPRequest",
                MagicMock(return_value=mock_req),
            )
            monkeypatch.setattr(
                "oid4vc.routes.vp_request.OID4VPPresentation",
                MagicMock(return_value=mock_pres),
            )

            session = _make_mock_session(storage_raises=True)
            monkeypatch.setattr(context, "session", MagicMock(return_value=session))

            mock_config = MagicMock()
            mock_config.endpoint = "http://localhost:8020"
            mock_config.oid4vp_endpoint = None
            monkeypatch.setattr(
                "oid4vc.routes.vp_request.Config.from_settings",
                MagicMock(return_value=mock_config),
            )

            request = vp_request_factory()
            response = await create_oid4vp_request(cast(web.Request, request))

            assert response.status == 200
            body = json.loads(response.body)
            assert "/tenant/" not in body["request_uri"]
        finally:
            if original is not None:
                context.profile.settings["wallet.id"] = original

    def test_old_guard_would_suppress_wallet_id(self, context):
        """Documents the pre-fix bug: the old guard silently omitted wallet.id.

        This is a pure logic regression test — no route call needed. It proves
        that a settings dict with wallet.id but without multitenant.enabled
        would have returned None under the old conditional.
        """
        settings = context.profile.settings

        # New behaviour: read directly
        wallet_id_new = settings.get("wallet.id")
        assert wallet_id_new is not None, "wallet.id must be present in test profile"

        # Old behaviour (re-implemented inline to document the bug)
        wallet_id_old = (
            settings.get("wallet.id") if settings.get("multitenant.enabled") else None
        )
        assert wallet_id_old is None, (
            "Old guard always returned None in single-wallet-askar mode because "
            "multitenant.enabled is absent from sub-wallet profile settings."
        )
