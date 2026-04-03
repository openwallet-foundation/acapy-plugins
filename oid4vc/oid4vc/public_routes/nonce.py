"""Nonce creation and request endpoints."""

import datetime

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.core.profile import Profile
from acapy_agent.messaging.util import datetime_now, datetime_to_str
from acapy_agent.storage.error import StorageError
from aiohttp import web
from aiohttp_apispec import docs
from secrets import token_urlsafe

from ..models.nonce import Nonce

NONCE_BYTES = 16
EXPIRES_IN = 86400


async def create_nonce(profile: Profile, nbytes: int, ttl: int) -> Nonce:
    """Create and store a fresh nonce."""
    nonce = token_urlsafe(nbytes)
    issued_at = datetime_now()
    expires_at = issued_at + datetime.timedelta(seconds=ttl)
    issued_at_str = datetime_to_str(issued_at)
    expires_at_str = datetime_to_str(expires_at)

    if issued_at_str is None or expires_at_str is None:
        raise web.HTTPInternalServerError(reason="Could not generate timestamps")

    try:
        nonce_record = Nonce(
            nonce_value=nonce,
            used=False,
            issued_at=issued_at_str,
            expires_at=expires_at_str,
        )
        async with profile.session() as session:
            await nonce_record.save(session, reason="Created new nonce")

        return nonce_record
    except StorageError as err:
        raise web.HTTPInternalServerError(reason="Could not store nonce") from err


@docs(tags=["oid4vci"], summary="Get a fresh nonce for proof of possession")
async def request_nonce(request: web.Request):
    """Get a fresh nonce for proof of possession."""
    context: AdminRequestContext = request["context"]
    nonce = await create_nonce(context.profile, NONCE_BYTES, EXPIRES_IN)

    return web.json_response(
        {
            "c_nonce": nonce.nonce_value,
            "expires_in": EXPIRES_IN,
        },
        headers={"Cache-Control": "no-store"},
    )
