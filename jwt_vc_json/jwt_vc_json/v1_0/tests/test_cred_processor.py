import pytest
from aries_cloudagent.admin.request_context import AdminRequestContext

from oid4vci.models.exchange import OID4VCIExchangeRecord
from oid4vci.models.supported_cred import SupportedCredential
from oid4vci.public_routes import PopResult

from ..cred_processor import CredProcessor


class TestCredentialProcessor:
    """Tests for CredentialProcessor."""

    @pytest.mark.asyncio
    async def test_issue_credential(
        self,
        body: any,
        supported: SupportedCredential,
        ex_record: OID4VCIExchangeRecord,
        pop: PopResult,
        context: AdminRequestContext,
    ):
        """Test issue_credential method."""

        cred_processor = CredProcessor()

        jws = cred_processor.issue_cred(body, supported, ex_record, pop, context)

        assert jws
