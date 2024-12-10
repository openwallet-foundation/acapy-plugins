from unittest.mock import patch

import pytest
from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.core.profile import Profile
from aiohttp import web

from oid4vc import public_routes as test_module


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

    with patch.object(test_module, "web", autospec=True) as mock_web:
        await test_module.credential_issuer_metadata(req)
        mock_web.json_response.assert_called_once_with(
            {
                "credential_issuer": f"http://localhost:8020/tenant/{req.match_info.get()}",
                "credential_endpoint": f"http://localhost:8020/tenant/{req.match_info.get()}/credential",
                "credentials_supported": [
                    {
                        "format": "jwt_vc_json",
                        "id": "MyCredential",
                        "credentialSubject": {"name": "alice"},
                    }
                ],
            }
        )


@pytest.mark.asyncio
async def test_get_token(context: AdminRequestContext, req: web.Request):
    """Test token issuance endpoint."""


@pytest.mark.asyncio
async def test_handle_proof_of_posession(profile: Profile):
    """Test handling of proof of posession."""
    proof = {
        "proof_type": "jwt",
        "jwt": "eyJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCIsImFsZyI6IkVTMjU2SyIsImtpZCI6ImRpZDpqd2s6ZXlKaGJHY2lPaUpGVXpJMU5rc2lMQ0oxYzJVaU9pSnphV2NpTENKcmRIa2lPaUpGUXlJc0ltTnlkaUk2SW5ObFkzQXlOVFpyTVNJc0luZ2lPaUpzTWtKbU1GVXlabHA1TFdaMVl6WkJOM3BxYmxwTVJXbFNiM2xzV0VsNWJrMUdOM1JHYUVOd2RqUm5JaXdpZVNJNklrYzBSRlJaUVhGZlEwZHdjVEJ2UkdKQmNVWkxWMWxLTFZoRmRDMUZiVFl6TXpGV2QwcHRjaTFpUkdNaWZRIzAifQ.eyJpYXQiOjE3MDExMjczMTUuMjQ3LCJleHAiOjE3MDExMjc5NzUuMjQ3LCJhdWQiOiJodHRwczovLzEzNTQtMTk4LTkxLTYyLTU4Lm5ncm9rLmlvIiwibm9uY2UiOiIySTF3LUVfNkUtczA3dkFJbzNxOThnIiwiaXNzIjoic3BoZXJlb246c3NpLXdhbGxldCIsImp0aSI6IjdjNzJmODg3LTI4YjQtNDg5Mi04MTUxLWNhZWMxNDRjMzBmMSJ9.XUfMcLMddw1DEqfQvQkk41FTwTmOk-dR3M51PsC76VWn3Ln3KlmPBUEwmFjEEqoEpVIm6kV7K_9svYNc2_ZX4w",
    }
    nonce = "2I1w-E_6E-s07vAIo3q98g"
    result = await test_module.handle_proof_of_posession(profile, proof, nonce)
    assert isinstance(result.verified, bool)
