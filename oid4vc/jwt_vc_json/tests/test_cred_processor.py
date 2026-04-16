from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from acapy_agent.admin.request_context import AdminRequestContext

from jwt_vc_json.cred_processor import JwtVcJsonCredProcessor
from oid4vc.models.exchange import OID4VCIExchangeRecord
from oid4vc.models.supported_cred import SupportedCredential
from oid4vc.public_routes import PopResult


class TestCredentialProcessor:
    """Tests for CredentialProcessor."""

    @pytest.mark.asyncio
    async def test_issue_credential(
        self,
        body: Any,
        supported: SupportedCredential,
        ex_record: OID4VCIExchangeRecord,
        pop: PopResult,
        context: AdminRequestContext,
    ):
        """Test issue_credential method."""

        cred_processor = JwtVcJsonCredProcessor()

        with patch(
            "jwt_vc_json.cred_processor.jwt_sign",
            AsyncMock(return_value="signed-jwt"),
        ):
            jws = await cred_processor.issue(body, supported, ex_record, pop, context)

        assert jws

    def test_credential_metadata_passes_through_spec_compliant_claims(self):
        """Test that spec-compliant claims array is passed through unchanged."""
        cred_processor = JwtVcJsonCredProcessor()

        supported_cred = {
            "format": "jwt_vc_json",
            "credential_metadata": {
                "claims": [
                    {
                        "path": ["permit"],
                        "display": [{"name": "Permit Name", "locale": "en-US"}],
                    }
                ]
            },
        }

        metadata = cred_processor.credential_metadata(supported_cred)

        assert metadata["credential_metadata"]["claims"] == [
            {
                "path": ["permit"],
                "display": [{"name": "Permit Name", "locale": "en-US"}],
            }
        ]
