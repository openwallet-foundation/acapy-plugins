"""Issue an SD-JWT credential."""

import datetime
from typing import Any
import uuid
from aries_cloudagent.admin.request_context import AdminRequestContext
from oid4vc.cred_processor import CredProcessor, CredIssueError
from oid4vc.models.exchange import OID4VCIExchangeRecord
from oid4vc.models.supported_cred import SupportedCredential
from oid4vc.pop_result import PopResult
from oid4vc.public_routes import types_are_subset


class SdJwtCredIssueError(CredProcessor):
    """Credential processor class for sd_jwt_vc format."""

    format = "sd_jwt_vc"

    async def issue_cred(
        self,
        body: Any,
        supported: SupportedCredential,
        ex_record: OID4VCIExchangeRecord,
        pop: PopResult,
        context: AdminRequestContext,
    ) -> Any:
        """Return a signed credential in SD-JWT format."""
        assert supported.format_data
        if not types_are_subset(body.get("types"), supported.format_data.get("types")):
            raise CredIssueError("Requested types does not match offer.")

        current_time = datetime.datetime.now(datetime.timezone.utc)
        current_time_unix_timestamp = int(current_time.timestamp())
        formatted_time = current_time.strftime("%Y-%m-%dT%H:%M:%SZ")
        cred_id = str(uuid.uuid4())
