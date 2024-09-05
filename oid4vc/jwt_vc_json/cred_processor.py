"""Issue a jwt_vc_json credential."""

import datetime
import logging
from typing import Any
import uuid

from aries_cloudagent.admin.request_context import AdminRequestContext

from oid4vc.models.exchange import OID4VCIExchangeRecord
from oid4vc.models.supported_cred import SupportedCredential
from oid4vc.public_routes import types_are_subset
from oid4vc.pop_result import PopResult
from oid4vc.cred_processor import CredProcessor, CredIssueError
from oid4vc.jwt import jwt_sign
from pydid import DIDUrl

LOGGER = logging.getLogger(__name__)


class JwtVcJsonCredProcessor(CredProcessor):
    """Credential processor class for jwt_vc_json format."""

    format = "jwt_vc_json"

    async def issue_cred(
        self,
        body: Any,
        supported: SupportedCredential,
        ex_record: OID4VCIExchangeRecord,
        pop: PopResult,
        context: AdminRequestContext,
    ) -> Any:
        """Return signed credential in JWT format."""
        assert supported.format_data
        if not types_are_subset(body.get("types"), supported.format_data.get("types")):
            raise CredIssueError("Requested types does not match offer.")

        current_time = datetime.datetime.now(datetime.timezone.utc)
        current_time_unix_timestamp = int(current_time.timestamp())
        formatted_time = current_time.strftime("%Y-%m-%dT%H:%M:%SZ")
        cred_id = str(uuid.uuid4())

        # note: Some wallets require that the "jti" and "id" are a uri
        if pop.holder_kid and pop.holder_kid.startswith("did:"):
            subject = DIDUrl(pop.holder_kid).did
        elif pop.holder_jwk:
            # TODO implement this
            raise ValueError("Unsupported pop holder value")
        else:
            raise ValueError("Unsupported pop holder value")

        payload = {
            "vc": {
                **(supported.vc_additional_data or {}),
                "id": f"urn:uuid:{cred_id}",
                "issuer": ex_record.issuer_id,
                "issuanceDate": formatted_time,
                "credentialSubject": {
                    **(ex_record.credential_subject or {}),
                    "id": subject,
                },
            },
            "iss": ex_record.issuer_id,
            "nbf": current_time_unix_timestamp,
            "jti": f"urn:uuid:{cred_id}",
            "sub": subject,
        }

        jws = await jwt_sign(
            context.profile,
            {},
            payload,
            verification_method=ex_record.verification_method,
        )

        return jws
