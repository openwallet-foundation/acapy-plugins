"""Nonce management for OID4VCI proof of possession."""

import datetime
import logging
from secrets import token_urlsafe

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.core.profile import Profile
from acapy_agent.messaging.util import datetime_now, datetime_to_str
from aiohttp import web
from aiohttp_apispec import docs

from ..models.nonce import Nonce
from .constants import EXPIRES_IN, NONCE_BYTES

LOGGER = logging.getLogger(__name__)


async def create_nonce(profile: Profile, nbytes: int, ttl: int) -> Nonce:
    """Create and store a fresh nonce."""
    nonce = token_urlsafe(nbytes)
    issued_at = datetime_now()
    expires_at = issued_at + datetime.timedelta(seconds=ttl)
    issued_at_str = datetime_to_str(issued_at)
    expires_at_str = datetime_to_str(expires_at)

    if issued_at_str is None or expires_at_str is None:
        raise web.HTTPInternalServerError(reason="Could not generate timestamps")

    nonce_record = Nonce(
        nonce_value=nonce,
        used=False,
        issued_at=issued_at_str,
        expires_at=expires_at_str,
    )
    async with profile.session() as session:
        await nonce_record.save(session=session, reason="Created new nonce")

    return nonce_record


@docs(tags=["oid4vci"], summary="Get a fresh nonce for proof of possession")
async def get_nonce(request: web.Request):
    """Get a fresh nonce for proof of possession."""
    context: AdminRequestContext = request["context"]
    nonce = await create_nonce(context.profile, NONCE_BYTES, EXPIRES_IN)

    response = web.json_response(
        {
            "c_nonce": nonce.nonce_value,
            "expires_in": EXPIRES_IN,
        }
    )
    # OID4VCI spec §8 requires Cache-Control: no-store on nonce endpoint responses
    response.headers["Cache-Control"] = "no-store"
    return response
