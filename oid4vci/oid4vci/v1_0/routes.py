"""Basic Messages Storage API Routes."""
import logging
from typing import Mapping
import secrets
import string
from aries_cloudagent.messaging.models.base_record import BaseExchangeRecord, BaseRecord

from aiohttp import web
from aiohttp_apispec import (
    docs,
    match_info_schema,
    querystring_schema,
    request_schema,
)
from aries_cloudagent.core.profile import Profile
from aries_cloudagent.messaging.models.openapi import OpenAPISchema
from aries_cloudagent.protocols.basicmessage.v1_0.message_types import SPEC_URI
from aries_cloudagent.utils.tracing import AdminAPIMessageTracingSchema
from marshmallow import fields

LOGGER = logging.getLogger(__name__)
code_size = 8  # TODO: check


class CredExRecordListQueryStringSchema(OpenAPISchema):
    """Parameters and validators for credential exchange record list query."""

    thread_id = fields.UUID(
        required=False,
        metadata={"description": "Thread identifier"},
    )
    role = fields.Str(
        required=False,
        metadata={"description": "Role assigned in credential exchange"},
    )
    state = fields.Str(
        required=False,
        metadata={"description": "Credential exchange state"},
    )


class CredStoreRequestSchema(OpenAPISchema):
    """Request schema for sending a credential store admin message."""

    credential_id = fields.Str(required=False)


class IssueCredSchemaCore(AdminAPIMessageTracingSchema):
    """Filter, auto-remove, comment, trace."""

    filter_ = fields.Str(
        required=True,
        data_key="filter",
        metadata={"description": "Credential specification criteria by format"},
    )
    auto_remove = fields.Bool(
        required=False,
        metadata={
            "description": (
                "Whether to remove the credential exchange record on completion"
                " (overrides --preserve-exchange-records configuration setting)"
            )
        },
    )
    comment = fields.Str(
        required=False,
        allow_none=True,
        metadata={"description": "Human-readable comment"},
    )

    credential_preview = fields.Str(required=False)

    replacement_id = fields.Str(
        required=False,
        allow_none=True,
        metadata={
            "description": "Optional identifier used to manage credential replacement",
        },
    )


class CredExIdMatchInfoSchema(OpenAPISchema):
    """Path parameters and validators for request taking credential exchange id."""

    cred_ex_id = fields.Str(
        required=True,
        metadata={
            "description": "Credential exchange identifier",
        },
    )


class CredentialOfferRecord(BaseExchangeRecord):
    def __init__(
        self,
        credential_issuer,
        credentials,
        grants,
    ):
        self.credential_issuer = credential_issuer
        self.credentials = credentials
        self.grants = grants


class GetCredentialOfferSchema(OpenAPISchema):
    """Schema for GetCredential"""

    credentials = fields.List(fields.Str())
    credential_issuer = fields.Str()
    user_pin_required = fields.Bool(required=False)
    exchange_id = fields.Str(required=False)


@docs(
    tags=["oid4vci"],
    summary="Fetch all credential exchange records",
)
@querystring_schema(CredExRecordListQueryStringSchema)
async def credential_exchange_list(request: web.BaseRequest):
    """Request handler for searching credential exchange records.

    Args:
        request: aiohttp request object

    Returns:
        The connection list response

    """
    pass


@docs(
    tags=["oid4vci"],
    summary="Fetch a single credential exchange record",
)
@match_info_schema(CredExIdMatchInfoSchema())
async def credential_exchange_retrieve(request: web.BaseRequest):
    """Request handler for fetching single credential exchange record.

    Args:
        request: aiohttp request object

    Returns:
        The credential exchange record

    """
    pass


@docs(
    tags=["oid4vci"],
    summary=("Create a credential exchange record"),
)
@request_schema(IssueCredSchemaCore())
async def credential_exchange_create(request: web.BaseRequest):
    """Request handler for creating a credential from attr values.

    The internal credential record will be created without the credential
    being sent to any connection.

    Args:
        request: aiohttp request object

    Returns:
        The credential exchange record

    """
    pass


async def _create_free_offer(
    profile: Profile,
    filt_spec: Mapping = None,
    connection_id: str = None,
    auto_issue: bool = False,
    auto_remove: bool = False,
    replacement_id: str = None,
    preview_spec: dict = None,
    comment: str = None,
    trace_msg: bool = None,
):
    """Create a credential offer and related exchange record."""
    pass


@docs(
    tags=["oid4vci"],
    summary="Store a received credential",
)
@match_info_schema(CredExIdMatchInfoSchema())
@request_schema(CredStoreRequestSchema())
async def credential_exchange_store(request: web.BaseRequest):
    """Request handler for storing credential.

    Args:
        request: aiohttp request object

    Returns:
        The credential exchange record

    """
    pass


@docs(
    tags=["oid4vci"],
    summary="Remove an existing credential exchange record",
)
@match_info_schema(CredExIdMatchInfoSchema())
async def credential_exchange_remove(request: web.BaseRequest):
    """Request handler for removing a credential exchange record.

    Args:
        request: aiohttp request object

    """
    pass


@docs(tags=["oid4vci"], summary="Get a credential offer")
@querystring_schema(GetCredentialOfferSchema())
async def get_cred_offer(request: web.BaseRequest):
    """
    Endpoint to retrieve an OIDC4VCI compliant offer, that
    can f.e. be used in QR-Code presented to a compliant wallet.
    """
    credentials = request.query["credentials"]
    credential_issuer_url = request.query["credential_issuer"]
    profile = request["context"].profile

    # TODO: check that the credential_issuer_url is associated with an issuer DID
    # TODO: check that the credential requested is offered by the issuer

    code = "".join(
        secrets.choice(string.ascii_uppercase + string.digits) for _ in range(code_size)
    )

    grants = {
        "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
            "pre-authorized_code": code,
            "user_pin_required": False,
        }
    }

    record = CredentialOfferRecord(
        credential_issuer=credential_issuer_url,
        credentials=credentials,
        grants=grants,
    )

    async with profile.session() as session:
        await record.save(session, reason="Save credential offer record.")

    return web.json_response(record)


async def register(app: web.Application):
    """Register routes."""
    # add in the message list(s) route
    app.add_routes(
        [
            web.get("/oid4vci/credential-offer", get_cred_offer, allow_head=False),
            web.get(
                "/oid4vci/records",
                credential_exchange_list,
                allow_head=False,
            ),
            web.get(
                "/oid4vci/records/{cred_ex_id}",
                credential_exchange_retrieve,
                allow_head=False,
            ),
            web.post("/oid4vci/create", credential_exchange_create),
            web.post(
                "/oid4vci/records/{cred_ex_id}/store",
                credential_exchange_store,
            ),
            web.delete(
                "/oid4vci/records/{cred_ex_id}",
                credential_exchange_remove,
            ),
        ]
    )


def post_process_routes(app: web.Application):
    """Amend swagger API."""

    # Add top-level tags description
    if "tags" not in app._state["swagger_dict"]:
        app._state["swagger_dict"]["tags"] = []
    app._state["swagger_dict"]["tags"].append(
        {
            "name": "oid4vci",
            "description": "oid4vci plugin",
            "externalDocs": {"description": "Specification", "url": SPEC_URI},
        }
    )
