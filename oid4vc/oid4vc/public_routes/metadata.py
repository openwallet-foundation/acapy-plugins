"""Credential issuer metadata endpoint."""

import logging

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.messaging.models.openapi import OpenAPISchema
from aiohttp import web
from aiohttp_apispec import (
    docs,
    response_schema,
)
from marshmallow import fields

from ..config import Config
from ..cred_processor import CredProcessors
from ..models.supported_cred import SupportedCredential
from ..models.issuer_config import IssuerConfiguration

LOGGER = logging.getLogger(__name__)


class BatchCredentialIssuanceSchema(OpenAPISchema):
    """Batch credential issuance schema."""

    batch_size = fields.Int(
        required=True, metadata={"description": "The maximum array size for the proofs"}
    )


class CredentialIssuerMetadataSchema(OpenAPISchema):
    """Credential issuer metadata schema."""

    credential_issuer = fields.Str(
        required=True,
        metadata={"description": "The credential issuer endpoint."},
    )
    authorization_servers = fields.List(
        fields.Str(),
        required=False,
        metadata={"description": "The authorization server endpoint."},
    )
    credential_endpoint = fields.Str(
        required=True,
        metadata={"description": "The credential endpoint."},
    )
    token_endpoint = fields.Str(
        required=False,
        metadata={"description": "The token endpoint."},
    )
    nonce_endpoint = fields.Str(
        required=False,
        metadata={"description": "The nonce endpoint."},
    )
    credential_configurations_supported = fields.List(
        fields.Dict(),
        metadata={"description": "The supported credentials."},
    )
    batch_credential_issuance = fields.Nested(
        BatchCredentialIssuanceSchema,
        required=False,
        metadata={"description": "The batch credential issuance. Currently ignored."},
    )


@docs(tags=["oid4vc"], summary="Get credential issuer metadata")
@response_schema(CredentialIssuerMetadataSchema())
async def credential_issuer_metadata(request: web.Request):
    """Credential issuer metadata endpoint."""
    context: AdminRequestContext = request["context"]
    config = Config.from_settings(context.settings)
    public_url = config.endpoint

    async with context.session() as session:
        supported_creds = await SupportedCredential.query(session)

        registered_processors = context.inject(CredProcessors)
        cred_config_supported = {}
        for supported in supported_creds:
            processor = registered_processors.issuer_for_format(supported.format)
            raw_metadata = supported.metadata()
            cred_metadata = processor.credential_metadata(raw_metadata)
            cred_config_supported[supported.identifier] = cred_metadata

        wallet_id = request.match_info.get("wallet_id")
        subpath = f"/tenant/{wallet_id}" if wallet_id else ""
        issuer_config = await IssuerConfiguration.retrieve_by_id(
            session, wallet_id or "default-wallet"
        )
        metadata = issuer_config.issuer_metadata(f"{public_url}{subpath}")
        metadata["credential_configurations_supported"] = cred_config_supported

    LOGGER.debug("METADATA: %s", metadata)

    return web.json_response(metadata)
