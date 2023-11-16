from unittest.mock import patch

from aiohttp import web
from aries_cloudagent.admin.request_context import AdminRequestContext
import pytest

from oid4vci.v1_0 import public_routes as test_module


@pytest.mark.asyncio
async def test_issuer_metadata(context: AdminRequestContext, req: web.Request):
    """Test issuer metadata endpoint."""
    supported = test_module.SupportedCredential(
        format="jwt_vc_json",
        identifier="MyCredential",
        format_data={
            "credentialSubject": {"name": "alice"},
        },
    )

    async with context.session() as session:
        await supported.save(session)

    with patch.object(
        test_module, "OID4VCI_ENDPOINT", "http://localhost:8020"
    ), patch.object(test_module, "web", autospec=True) as mock_web:
        await test_module.oid_cred_issuer(req)
        mock_web.json_response.assert_called_once_with(
            {
                "credential_issuer": "http://localhost:8020/",
                "credential_endpoint": "http://localhost:8020/credential",
                "credentials_supported": [
                    {
                        "format": "jwt_vc_json",
                        "id": "MyCredential",
                        "credentialSubject": {"name": "alice"},
                    }
                ],
            }
        )
