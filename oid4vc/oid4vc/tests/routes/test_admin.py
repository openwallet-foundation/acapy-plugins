from unittest.mock import AsyncMock, MagicMock

import pytest
from acapy_agent.admin.request_context import AdminRequestContext

from oid4vc import routes as test_module
from oid4vc.models.supported_cred import SupportedCredential


@pytest.mark.asyncio
async def test_credential_supported_create(context: AdminRequestContext):
    """Test credential_supported_create endpoint."""

    request_dict = {
        "context": context,
        "outbound_message_router": AsyncMock(),
    }
    request = MagicMock(
        app={},
        match_info={},
        query={},
        __getitem__=lambda _, k: request_dict[k],
        headers={"x-api-key": "admin_api_key"},
        json=AsyncMock(
            return_value={
                "format": "jwt_vc_json",
                "id": "MyCredential",
                "format_data": {
                    "credentialSubject": {"name": "alice"},
                    "types": ["VerifiableCredential", "MyCredential"],
                },
                "cryptographic_binding_methods_supported": ["proof"],
                "cryptographic_suites_supported": ["ES256"],
                "display": [{"some nonsense": "here"}],
            }
        ),
    )

    await test_module.supported_credential_create(request)

    async with context.session() as session:
        records = await SupportedCredential.query(session, {"identifier": "MyCredential"})

    assert records
    record = records[0]
    assert record
    assert record.format == "jwt_vc_json"
    assert record.identifier == "MyCredential"
    assert record.format_data == {
        "credentialSubject": {"name": "alice"},
        "types": ["VerifiableCredential", "MyCredential"],
    }
