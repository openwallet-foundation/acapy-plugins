from typing import cast
from unittest.mock import AsyncMock, MagicMock

import pytest
from aiohttp import web

from acapy_agent.resolver.did_resolver import DIDResolver

from oid4vc.cred_processor import CredProcessors
from oid4vc.models.exchange import OID4VCIExchangeRecord
from oid4vc.models.supported_cred import SupportedCredential
from oid4vc.routes.exchange import (
    create_exchange,
    credential_refresh,
    exchange_create,
)
from oid4vc.routes.helpers import (
    _create_pre_auth_code,
    _parse_cred_offer,
)


@pytest.fixture
def dummy_request(context):
    class DummyRequest:
        def __init__(
            self,
            json_data=None,
            headers=None,
            path="/dummy-path",
            match_info=None,
        ):
            self._json = json_data or {
                "did": "did:key:z6MkvtXw2eu715zQ3vzCh1FQNNhkdVhpzHKh4L5sVPGZ6Mcs",
                "supported_cred_id": "cred_id",
                "credential_subject": {"name": "alice"},
            }
            self.headers = headers or {"Authorization": "Bearer testtoken"}
            self.path = path
            self.match_info = match_info or {}

        async def json(self):
            return self._json

        def __getitem__(self, key):
            if key == "context":
                return context
            raise KeyError(key)

    return DummyRequest


@pytest.mark.asyncio
async def test_create_pre_auth_code(monkeypatch, profile, config):
    # Patch AppResources.get_http_client().post to return a mock response
    mock_client = MagicMock()
    mock_response = MagicMock()
    mock_response.json = AsyncMock(return_value={"pre_authorized_code": "code123"})
    mock_client.post = AsyncMock(return_value=mock_response)
    monkeypatch.setattr(
        "oid4vc.routes.helpers.AppResources.get_http_client", lambda: mock_client
    )
    # Patch get_auth_header to return a dummy header
    monkeypatch.setattr(
        "oid4vc.routes.helpers.get_auth_header",
        AsyncMock(return_value="Bearer dummyheader"),
    )
    code = await _create_pre_auth_code(
        profile, config, "subject_id", "cred_config_id", "1234"
    )
    assert code == "code123"


@pytest.mark.asyncio
async def test_parse_cred_offer(monkeypatch, context):
    # Patch OID4VCIExchangeRecord.retrieve_by_id and SupportedCredential.retrieve_by_id
    mock_record = MagicMock(spec=OID4VCIExchangeRecord)
    mock_record.supported_cred_id = "cred_id"
    mock_record.pin = "1234"
    mock_record.refresh_id = "refresh_id"
    mock_record.code = None
    mock_record.state = None
    mock_record.save = AsyncMock()
    monkeypatch.setattr(
        "oid4vc.routes.helpers.OID4VCIExchangeRecord.retrieve_by_id",
        AsyncMock(return_value=mock_record),
    )
    mock_supported = MagicMock(spec=SupportedCredential)
    mock_supported.identifier = "cred_id"
    mock_supported.format = "jwt_vc_json"
    monkeypatch.setattr(
        "oid4vc.routes.helpers.SupportedCredential.retrieve_by_id",
        AsyncMock(return_value=mock_supported),
    )
    monkeypatch.setattr(
        "oid4vc.routes.helpers._create_pre_auth_code", AsyncMock(return_value="code123")
    )
    offer = await _parse_cred_offer(context, "exchange_id")
    assert offer["credential_issuer"].startswith("http://localhost:8020")
    assert (
        offer["grants"]["urn:ietf:params:oauth:grant-type:pre-authorized_code"][
            "pre-authorized_code"
        ]
        == "code123"
    )


@pytest.mark.asyncio
async def test_create_exchange(monkeypatch, context, dummy_request):
    context.profile.inject_or(DIDResolver)
    # Patch SupportedCredential.retrieve_by_id
    mock_supported = MagicMock(spec=SupportedCredential)
    mock_supported.identifier = "cred_id"
    mock_supported.format = "jwt_vc_json"
    monkeypatch.setattr(
        "oid4vc.routes.exchange.SupportedCredential.retrieve_by_id",
        AsyncMock(return_value=mock_supported),
    )
    # Patch CredProcessors
    mock_processor = MagicMock()
    mock_processor.validate_credential_subject = MagicMock()
    mock_processors = MagicMock()
    mock_processors.issuers = {"jwt_vc_json": mock_processor}
    mock_processors.issuer_for_format = MagicMock(return_value=mock_processor)
    context.profile.context.injector.bind_instance(CredProcessors, mock_processors)
    # Patch OID4VCIExchangeRecord.save
    monkeypatch.setattr("oid4vc.routes.exchange.OID4VCIExchangeRecord.save", AsyncMock())

    request = dummy_request()
    record = await create_exchange(cast(web.Request, request))
    assert isinstance(record, OID4VCIExchangeRecord)
    assert record.credential_subject["name"] == "alice"


@pytest.mark.asyncio
async def test_exchange_create(monkeypatch, dummy_request):
    # Patch create_exchange to return a mock record
    mock_record = MagicMock(spec=OID4VCIExchangeRecord)
    mock_record.serialize.return_value = {
        "id": "exchange_id",
        "credential_subject": {"name": "alice"},
    }
    monkeypatch.setattr(
        "oid4vc.routes.exchange.create_exchange", AsyncMock(return_value=mock_record)
    )

    request = dummy_request()
    resp = await exchange_create(cast(web.Request, request))
    assert isinstance(resp, web.Response)
    assert resp.body


@pytest.mark.asyncio
async def test_credential_refresh(monkeypatch, dummy_request):
    # Patch OID4VCIExchangeRecord.retrieve_by_refresh_id
    mock_existing = MagicMock(spec=OID4VCIExchangeRecord)
    mock_existing.state = OID4VCIExchangeRecord.STATE_CREATED
    mock_existing.save = AsyncMock()
    monkeypatch.setattr(
        "oid4vc.routes.exchange.OID4VCIExchangeRecord.retrieve_by_refresh_id",
        AsyncMock(return_value=mock_existing),
    )
    # Patch create_exchange
    mock_record = MagicMock(spec=OID4VCIExchangeRecord)
    mock_record.serialize.return_value = {
        "id": "exchange_id",
        "credential_subject": {"name": "alice"},
    }
    monkeypatch.setattr(
        "oid4vc.routes.exchange.create_exchange", AsyncMock(return_value=mock_record)
    )

    request = dummy_request()
    request.match_info = {"refresh_id": "refresh_id"}
    resp = await credential_refresh(cast(web.Request, request))
    assert isinstance(resp, web.Response)
    assert resp.body
