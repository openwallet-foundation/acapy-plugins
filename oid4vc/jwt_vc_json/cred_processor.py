"""Issue a jwt_vc_json credential."""

import datetime
import logging
import uuid
from typing import Any

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.core.profile import Profile
from pydid import DIDUrl

from oid4vc.cred_processor import (
    CredProcessorError,
    CredVerifier,
    Issuer,
    PresVerifier,
    VerifyResult,
)
from oid4vc.jwt import jwt_sign, jwt_verify
from oid4vc.models.exchange import OID4VCIExchangeRecord
from oid4vc.models.presentation import OID4VPPresentation
from oid4vc.models.supported_cred import SupportedCredential
from oid4vc.pop_result import PopResult
from oid4vc.public_routes import types_are_subset
from oid4vc.status_handler import StatusHandler

LOGGER = logging.getLogger(__name__)


class JwtVcJsonCredProcessor(Issuer, CredVerifier, PresVerifier):
    """Credential processor class for jwt_vc_json format."""

    async def issue(
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
            raise CredProcessorError("Requested types does not match offer.")

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

        status_handler = context.inject_or(StatusHandler)
        if status_handler and (
            credential_status := await status_handler.assign_status_entries(
                context, supported.supported_cred_id, ex_record.exchange_id
            )
        ):
            payload["vc"]["credentialStatus"] = credential_status
            LOGGER.debug("credential with status: %s", payload)

        jws = await jwt_sign(
            context.profile,
            {},
            payload,
            verification_method=ex_record.verification_method,
        )

        return jws

    def validate_credential_subject(self, supported: SupportedCredential, subject: dict):
        """Validate the credential subject."""
        pass

    def validate_supported_credential(self, supported: SupportedCredential):
        """Validate a supported JWT VC JSON Credential."""
        pass

    async def verify(self, profile: Profile, jwt: str) -> VerifyResult:
        """Verify a credential or presentation."""
        res = await jwt_verify(profile, jwt)
        return VerifyResult(
            verified=res.verified,
            payload=res.payload,
        )

    async def verify_credential(
        self,
        profile: Profile,
        credential: Any,
    ) -> VerifyResult:
        """Verify a credential in JWT VC format."""
        return await self.verify(profile, credential)

    async def verify_presentation(
        self,
        profile: Profile,
        presentation: Any,
        presentation_record: OID4VPPresentation,
    ) -> VerifyResult:
        """Verify a presentation in JWT VP format."""
        return await self.verify(profile, presentation)
