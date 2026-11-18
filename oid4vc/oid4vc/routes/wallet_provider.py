"""Wallet Provider registry routes: trusted signers of Key Attestations."""

from typing import Any, Optional

from acapy_agent.admin.decorators.auth import tenant_authentication
from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.messaging.models.openapi import OpenAPISchema
from acapy_agent.storage.error import StorageError, StorageNotFoundError
from aiohttp import web
from aiohttp_apispec import docs, match_info_schema, request_schema, response_schema
from marshmallow import fields

from ..key_attestation import signing_alg
from ..models.wallet_provider import WalletProvider, WalletProviderSchema


class WalletProviderCreateSchema(OpenAPISchema):
    """Request schema for creating a Wallet Provider."""

    iss = fields.Str(
        required=True,
        metadata={
            "description": "Issuer of the provider's Key Attestations, matched verbatim",
            "example": "https://wallet.example.com",
        },
    )
    jwks = fields.Dict(
        required=False,
        allow_none=True,
        metadata={
            "description": (
                "Inline JWKS of P-256, P-384, secp256k1 or Ed25519 keys, each with "
                "a kid. Not allowed with jwks_uri"
            ),
            "example": {
                "keys": [
                    {
                        "kid": "wallet-example-key-1",
                        "kty": "EC",
                        "crv": "P-256",
                        "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                        "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
                    }
                ]
            },
        },
    )
    jwks_uri = fields.Str(
        required=False,
        allow_none=True,
        metadata={
            "description": "https URL of the provider's JWKS. Not allowed with jwks"
        },
    )
    name = fields.Str(required=False, allow_none=True)
    active = fields.Bool(required=False)


class WalletProviderUpdateSchema(WalletProviderCreateSchema):
    """Request schema for updating a Wallet Provider; all fields optional."""

    iss = fields.Str(required=False)


class WalletProviderMatchSchema(OpenAPISchema):
    """Path parameters for a Wallet Provider."""

    wallet_provider_id = fields.Str(
        required=True, metadata={"description": "Wallet Provider record identifier"}
    )


class WalletProviderListSchema(OpenAPISchema):
    """Wallet Provider list response."""

    results = fields.List(fields.Nested(WalletProviderSchema()))


def _check_fields(iss: Any, jwks: Optional[dict], jwks_uri: Optional[str]):
    if not isinstance(iss, str) or not iss:
        raise web.HTTPBadRequest(reason="iss is required")
    if not jwks and not jwks_uri:
        raise web.HTTPBadRequest(reason="Either jwks or jwks_uri is required")
    if jwks and jwks_uri:
        raise web.HTTPBadRequest(reason="Only one of jwks or jwks_uri may be set")
    if jwks_uri and not jwks_uri.startswith("https://"):
        raise web.HTTPBadRequest(reason="jwks_uri must use https")
    if jwks:
        keys = jwks.get("keys")
        if not isinstance(keys, list) or not keys:
            raise web.HTTPBadRequest(reason="jwks must contain a non-empty keys array")
        for key in keys:
            if not isinstance(key, dict) or not isinstance(key.get("kid"), str):
                raise web.HTTPBadRequest(reason="Each jwks key needs a kid")
            try:
                alg = signing_alg(key)
            except ValueError as err:
                raise web.HTTPBadRequest(reason=f"Invalid jwks key: {err}") from err
            # Such a key is skipped or fails verification, so it can never verify
            if key.get("use", "sig") != "sig" or key.get("alg", alg) != alg:
                raise web.HTTPBadRequest(
                    reason=f"Invalid jwks key: {key['kid']} needs use sig and alg {alg}"
                )


async def _check_iss_unique(session, iss: str, record_id: Optional[str] = None):
    existing = await WalletProvider.query(session, {"iss": iss})
    if any(record.wallet_provider_id != record_id for record in existing):
        raise web.HTTPBadRequest(reason=f"A Wallet Provider with iss {iss} exists")


@docs(tags=["oid4vci"], summary="Register a Wallet Provider trusted for Key Attestations")
@request_schema(WalletProviderCreateSchema())
@response_schema(WalletProviderSchema())
@tenant_authentication
async def wallet_provider_create(request: web.Request):
    """Create a Wallet Provider."""
    context: AdminRequestContext = request["context"]
    body = await request.json()
    _check_fields(body.get("iss"), body.get("jwks"), body.get("jwks_uri"))
    record = WalletProvider(
        iss=body["iss"],
        jwks=body.get("jwks"),
        jwks_uri=body.get("jwks_uri"),
        name=body.get("name"),
        active=body.get("active", True),
    )
    try:
        async with context.session() as session:
            await _check_iss_unique(session, record.iss)
            await record.save(session, reason="Created Wallet Provider")
    except StorageError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err
    return web.json_response(record.serialize())


@docs(tags=["oid4vci"], summary="List Wallet Providers")
@response_schema(WalletProviderListSchema())
@tenant_authentication
async def wallet_provider_list(request: web.Request):
    """List Wallet Providers."""
    context: AdminRequestContext = request["context"]
    try:
        async with context.session() as session:
            records = await WalletProvider.query(session)
    except StorageError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err
    return web.json_response({"results": [record.serialize() for record in records]})


@docs(tags=["oid4vci"], summary="Get a Wallet Provider")
@match_info_schema(WalletProviderMatchSchema())
@response_schema(WalletProviderSchema())
@tenant_authentication
async def wallet_provider_get(request: web.Request):
    """Get a Wallet Provider."""
    context: AdminRequestContext = request["context"]
    try:
        async with context.session() as session:
            record = await WalletProvider.retrieve_by_id(
                session, request.match_info["wallet_provider_id"]
            )
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err
    except StorageError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err
    return web.json_response(record.serialize())


@docs(tags=["oid4vci"], summary="Update a Wallet Provider")
@match_info_schema(WalletProviderMatchSchema())
@request_schema(WalletProviderUpdateSchema())
@response_schema(WalletProviderSchema())
@tenant_authentication
async def wallet_provider_update(request: web.Request):
    """Update a Wallet Provider; omitted fields are unchanged."""
    context: AdminRequestContext = request["context"]
    body = await request.json()
    try:
        async with context.session() as session:
            record = await WalletProvider.retrieve_by_id(
                session, request.match_info["wallet_provider_id"], for_update=True
            )
            for field in ("iss", "jwks", "jwks_uri", "name", "active"):
                if field in body:
                    setattr(record, field, body[field])
            _check_fields(record.iss, record.jwks, record.jwks_uri)
            await _check_iss_unique(session, record.iss, record.wallet_provider_id)
            await record.save(session, reason="Updated Wallet Provider")
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err
    except StorageError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err
    return web.json_response(record.serialize())


@docs(tags=["oid4vci"], summary="Delete a Wallet Provider")
@match_info_schema(WalletProviderMatchSchema())
@response_schema(WalletProviderSchema())
@tenant_authentication
async def wallet_provider_delete(request: web.Request):
    """Delete a Wallet Provider."""
    context: AdminRequestContext = request["context"]
    try:
        async with context.session() as session:
            record = await WalletProvider.retrieve_by_id(
                session, request.match_info["wallet_provider_id"]
            )
            await record.delete_record(session)
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err
    except StorageError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err
    return web.json_response(record.serialize())
