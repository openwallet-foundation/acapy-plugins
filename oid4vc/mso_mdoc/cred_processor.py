"""Issue a mso_mdoc credential."""

import json
import logging
import re
import base64
from typing import Any

from acapy_agent.admin.request_context import AdminRequestContext

from oid4vc.cred_processor import CredProcessorError, Issuer
from oid4vc.models.exchange import OID4VCIExchangeRecord
from oid4vc.models.supported_cred import SupportedCredential
from oid4vc.pop_result import PopResult

from .mdoc import mso_mdoc_sign

LOGGER = logging.getLogger(__name__)


class MsoMdocCredProcessor(Issuer):
    """Credential processor class for mso_mdoc credential format."""

    async def issue(
        self,
        body: Any,
        supported: SupportedCredential,
        ex_record: OID4VCIExchangeRecord,
        pop: PopResult,
        context: AdminRequestContext,
    ):
        LOGGER.debug("supported credential: %s", supported)
        """Return signed credential in COBR format."""
        assert supported.doctype
        if body.get("doctype") != supported.doctype:
            raise CredProcessorError("Requested doctype does not match offer.")

        try:
            headers = {
                "doctype": supported.doctype,
                "deviceKey": re.sub(
                    "did:(.+?):(.+?)#(.*)",
                    "\\2",
                    json.dumps(pop.holder_jwk or pop.holder_kid),
                ),
            }
            did = None
            verification_method = ex_record.verification_method
            payload = ex_record.credential_subject
            mso_mdoc = await mso_mdoc_sign(
                context.profile, headers, payload, did, verification_method
            )
            mso_mdoc = mso_mdoc[2:-1] if mso_mdoc.startswith("b'") else None
        except Exception as ex:
            raise CredProcessorError("Failed to issue credential") from ex

        binary = bytes.fromhex(mso_mdoc)
        mso_mdoc_base64url = base64.urlsafe_b64encode(binary).rstrip(b'=').decode('ascii')    
        return mso_mdoc_base64url

    def validate_credential_subject(self, supported: SupportedCredential, subject: dict):
        """Validate the credential subject."""
        pass

    def validate_supported_credential(self, supported: SupportedCredential):
        """Validate a supported MSO MDOC Credential."""
        pass
