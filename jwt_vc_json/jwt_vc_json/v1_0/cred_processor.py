"""Issue a jwt_vc_json credential."""

import datetime
import logging
import uuid

from aries_cloudagent.admin.request_context import AdminRequestContext
from aries_cloudagent.wallet.jwt import jwt_sign

from oid4vci.models.exchange import OID4VCIExchangeRecord
from oid4vci.models.supported_cred import SupportedCredential
from oid4vci.public_routes import types_are_subset
from oid4vci.pop_result import PopResult
from oid4vci.cred_processor import ICredProcessor, CredIssueError

LOGGER = logging.getLogger(__name__)


class CredProcessor(ICredProcessor):
    """Credential processor class for jwt_vc_json format."""

    async def issue_cred(
        self,
        body: any,
        supported: SupportedCredential,
        ex_record: OID4VCIExchangeRecord,
        pop: PopResult,
        context: AdminRequestContext,
    ):
        """Return signed credential in JWT format."""
        if not types_are_subset(body.get("types"), supported.format_data.get("types")):
            raise CredIssueError("Requested types does not match offer.")

        current_time = datetime.datetime.now(datetime.timezone.utc)
        current_time_unix_timestamp = int(current_time.timestamp())
        formatted_time = current_time.strftime("%Y-%m-%dT%H:%M:%SZ")
        cred_id = str(uuid.uuid4())

        # note: Some wallets require that the "jti" and "id" are a uri
        payload = {
            "vc": {
                **(supported.vc_additional_data or {}),
                "id": f"urn:uuid:{cred_id}",
                "issuer": ex_record.issuer_id,
                "issuanceDate": formatted_time,
                "credentialSubject": {
                    **(ex_record.credential_subject or {}),
                    "id": pop.holder_kid,
                },
            },
            "iss": ex_record.issuer_id,
            "nbf": current_time_unix_timestamp,
            "jti": f"urn:uuid:{cred_id}",
            "sub": pop.holder_kid,
        }

        jws = await jwt_sign(
            context.profile,
            {},
            payload,
            verification_method=ex_record.verification_method,
        )

        return jws
