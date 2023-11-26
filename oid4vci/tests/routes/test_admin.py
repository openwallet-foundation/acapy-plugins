from aiohttp import web
from unittest.mock import AsyncMock
from aries_cloudagent.admin.request_context import AdminRequestContext
from oid4vci import routes as test_module
import pytest

from oid4vci.models.supported_cred import SupportedCredential


@pytest.mark.asyncio
async def test_credential_supported_create(
    context: AdminRequestContext, req: web.Request
):
    """Test credential_supported_create endpoint."""
    req.json = AsyncMock(
        return_value={
            "format": "jwt_vc_json",
            "id": "MyCredential",
            "credentialSubject": {"name": "alice"},
            "type": ["VerifiableCredential", "MyCredential"],
            "cryptographic_binding_methods_supported": ["proof"],
            "cryptographic_suites_supported": ["ES256"],
            "display": [{"some nonsense": "here"}],
        }
    )

    await test_module.credential_supported_create(req)

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
        "type": ["VerifiableCredential", "MyCredential"],
    }
