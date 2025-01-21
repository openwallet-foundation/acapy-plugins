from typing import Any

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

        jws = cred_processor.issue(body, supported, ex_record, pop, context)

        assert jws
