"""Issue a mso_mdoc credential."""

import logging, re

from aiohttp import web
from aries_cloudagent.admin.request_context import AdminRequestContext

from oid4vci.models.exchange import OID4VCIExchangeRecord
from oid4vci.models.supported_cred import SupportedCredential
from oid4vci.public_routes import PopResult, ICredProcessor

from .mdoc import mso_mdoc_sign

LOGGER = logging.getLogger(__name__)


class CredProcessor(ICredProcessor):

    async def issue_cred(
        self,
        body: any,
        supported: SupportedCredential,
        ex_record: OID4VCIExchangeRecord,
        pop: PopResult,
        context: AdminRequestContext,
    ):
        if body.get("doctype") != supported.format_data.get("doctype"):
            raise web.HTTPBadRequest(reason="Requested types does not match offer.")

        try:
            headers = {
                "doctype": supported.format_data.get("doctype"),
                "deviceKey": re.sub(
                    "did:(.+?):(.+?)#(.*)", "\\2", (pop.holder_jwk or pop.holder_kid)
                ),
            }
            did = None
            verification_method = ex_record.verification_method
            payload = ex_record.credential_subject
            mso_mdoc = await mso_mdoc_sign(
                context.profile, headers, payload, did, verification_method
            )
        except ValueError as err:
            raise web.HTTPBadRequest(reason="Failed to issue credential") from err

        return mso_mdoc
