"""Credential offer dereference endpoint."""

import json
from urllib.parse import quote

from acapy_agent.admin.request_context import AdminRequestContext
from aiohttp import web
from aiohttp_apispec import (
    docs,
    querystring_schema,
    response_schema,
)

from ..routes import _parse_cred_offer, CredOfferQuerySchema, CredOfferResponseSchemaVal


@docs(tags=["oid4vci"], summary="Dereference a credential offer.")
@querystring_schema(CredOfferQuerySchema())
@response_schema(CredOfferResponseSchemaVal(), 200)
async def dereference_cred_offer(request: web.BaseRequest):
    """Dereference a credential offer.

    Reference URI is acquired from the /oid4vci/credential-offer-by-ref endpoint
    (see routes.get_cred_offer_by_ref()).
    """
    context: AdminRequestContext = request["context"]
    exchange_id = request.query["exchange_id"]

    offer = await _parse_cred_offer(context, exchange_id)
    return web.json_response(
        {
            "offer": offer,
            "credential_offer": f"openid-credential-offer://?credential_offer={quote(json.dumps(offer))}",
        }
    )
