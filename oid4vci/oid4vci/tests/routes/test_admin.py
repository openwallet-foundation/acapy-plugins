from unittest.mock import AsyncMock, MagicMock

import pytest
from aries_cloudagent.admin.request_context import AdminRequestContext
from aries_cloudagent.core.in_memory.profile import InMemoryProfile

from oid4vci import routes as test_module
from oid4vci.models.supported_cred import SupportedCredential


@pytest.mark.asyncio
async def test_credential_supported_create():
    """Test credential_supported_create endpoint."""

    profile = InMemoryProfile.test_profile(
        settings={
            "admin.admin_insecure_mode": True,
        }
    )
    context = AdminRequestContext.test_context({}, profile)
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
        )
    )

    await test_module.supported_credential_create(request)

    async with context.session() as session:
        records = await SupportedCredential.query(
            session, {"identifier": "MyCredential"}
        )

    assert records
    record = records[0]
    assert record
    assert record.format == "jwt_vc_json"
    assert record.identifier == "MyCredential"
    assert record.format_data == {
        "credentialSubject": {"name": "alice"},
        "types": ["VerifiableCredential", "MyCredential"],
    }
