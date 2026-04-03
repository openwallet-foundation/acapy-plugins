"""Issuer configuration endpoints."""

import logging

from acapy_agent.admin.decorators.auth import tenant_authentication
from acapy_agent.messaging.models.openapi import OpenAPISchema
from acapy_agent.storage.error import StorageNotFoundError
from aiohttp import web
from aiohttp_apispec import (
    docs,
    request_schema,
    response_schema,
)
from marshmallow import fields

from ..models.issuer_config import IssuerConfiguration

LOGGER = logging.getLogger(__name__)


class IssuerConfigInfoSchema(OpenAPISchema):
    """Schema for Issuer Configuration."""

    credential_issuer = fields.Str(required=False, description="credential issuer")
    authorization_servers = fields.List(
        fields.Dict(),
        metadata={
            "example": [
                {
                    "public_url": "https://auth.example.com",
                    "private_url": "https://intra.example.com",
                    "auth_type": "client_secret_basic",
                    "client_credentials": {
                        "client_id": "abc123",
                        "client_secret": "xyz456",
                    },
                },
                {
                    "public_url": "https://auth.example.com",
                    "private_url": "https://intra.example.com",
                    "auth_type": "private_key_jwt",
                    "client_credentials": {
                        "client_id": "abc123",
                        "did": "wV6ydFNQYCdo2mfzvPBbF",
                    },
                },
            ]
        },
    )
    credential_endpoint = fields.Str(required=False, description="credential endpoint")
    nonce_endpoint = fields.Str(required=False, description="nonce endpoint")
    deferred_credential_endpoint = fields.Str(
        required=False, description="deferred credential endpoint"
    )
    notification_endpoint = fields.Str(
        required=False, description="notification endpoint"
    )
    credential_request_encryption = fields.Dict(
        required=False,
        metadata={
            "example": {
                "keys": [
                    {
                        "kty": "EC",
                        "crv": "P-256",
                        "x": "f83OJ3D2xF4Jqk8rVqYf5UEoR2L7iB42t1R6kzjzA6o",
                        "y": "x_FEzRu9yQ1rZtQxCkVwYg1oHc3mG5m0kYqf9u0Qf6A",
                        "use": "enc",
                        "alg": "ECDH-ES",
                        "key_ops": ["deriveKey", "deriveBits"],
                        "kid": "ec-p256-enc-1",
                    }
                ]
            },
            "enc_values_supported": ["A256GCM", "A128GCM", "A128CBC-HS256"],
            "zip_values_supported": ["DEF"],
            "encryption_required": True,
        },
    )
    credential_response_encryption = fields.Dict(
        required=False,
        metadata={
            "example": {
                "alg_values_supported": [
                    "ECDH-ES",
                    "ECDH-ES+A256KW",
                    "RSA-OAEP-256",
                    "RSA-OAEP",
                ],
                "enc_values_supported": ["A256GCM", "A128GCM", "A128CBC-HS256"],
                "zip_values_supported": ["DEF"],
                "encryption_required": True,
            },
        },
    )
    batch_credential_issuance = fields.Dict(
        required=False,
        metadata={
            "example": {"batch_size": 100},
        },
    )
    display = fields.List(
        fields.Dict(),
        metadata={
            "example": [
                {
                    "name": "University Credential",
                    "locale": "en-US",
                    "logo": {
                        "uri": "https://exampleuniversity.com/public/logo.png",
                        "alt_text": "a square logo of a university",
                    },
                }
            ]
        },
    )


@docs(
    tags=["oid4vci"],
    summary="Retrieve issuer configuration information",
)
@response_schema(IssuerConfigInfoSchema(), 200)
@tenant_authentication
async def get_issuer_config(request: web.BaseRequest):
    """Request handler for retrieving issuer configuration."""
    context = request["context"]
    wallet_id = (
        context.profile.settings.get("wallet.id")
        if context.profile.settings.get("multitenant.enabled")
        else "default-wallet"
    )
    async with context.profile.session() as session:
        config = await IssuerConfiguration.retrieve_by_id(session, wallet_id)
        if config:
            return web.json_response(config.serialize())
        return web.json_response({}, status=404)


@docs(
    tags=["oid4vci"],
    summary="Upsert issuer configuration information",
)
@request_schema(IssuerConfigInfoSchema())
@response_schema(IssuerConfigInfoSchema(), 200)
@tenant_authentication
async def upsert_issuer_config(request: web.BaseRequest):
    """Request handler for upserting issuer configuration."""
    context = request["context"]
    wallet_id = (
        context.profile.settings.get("wallet.id")
        if context.profile.settings.get("multitenant.enabled")
        else "default-wallet"
    )
    body = await request.json()
    # Remove configuration_id from body to prevent override
    body.pop("configuration_id", None)
    async with context.profile.session() as session:
        try:
            config = await IssuerConfiguration.retrieve_by_id(session, wallet_id)
            if config:
                for attr in IssuerConfiguration.ISSUER_ATTRS:
                    setattr(config, attr, body[attr] if attr in body else None)
                await config.save(session)
        except StorageNotFoundError:
            config = IssuerConfiguration(
                configuration_id=wallet_id, new_with_id=True, **body
            )
            await config.save(session)
    return web.json_response(config.serialize())
