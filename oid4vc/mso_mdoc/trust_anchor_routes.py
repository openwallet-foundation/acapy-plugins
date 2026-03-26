"""mso_mdoc trust anchor and signing key admin routes.

Provides CRUD endpoints for managing:
- ``TrustAnchorRecord``: X.509 CA certificates trusted for mDoc verification
- ``MdocSigningKeyRecord``: EC private keys and certificates for mDoc issuance

These records replace the previous pattern of cramming signing material and
trust anchors into ``SupportedCredential.vc_additional_data``.  Using
``BaseRecord`` gives multi-tenant isolation automatically through profile
session scoping.
"""

import logging

from aiohttp import web
from aiohttp_apispec import (
    docs,
    match_info_schema,
    querystring_schema,
    request_schema,
    response_schema,
)
from acapy_agent.admin.decorators.auth import tenant_authentication
from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.messaging.models.base import BaseModelError
from acapy_agent.messaging.models.openapi import OpenAPISchema
from acapy_agent.storage.error import StorageError, StorageNotFoundError
from marshmallow import fields

from .trust_anchor import TrustAnchorRecord, TrustAnchorRecordSchema
from .signing_key import (
    MdocSigningKeyRecord,
    MdocSigningKeyRecordSchema,
    MdocSigningKeyCreateSchema,
    MdocSigningKeyImportSchema,
    MdocSigningKeyUpdateSchema,
    generate_ec_p256_key_pem,
    validate_cert_matches_private_key,
)

LOGGER = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helper schemas
# ---------------------------------------------------------------------------


class TrustAnchorIdMatchSchema(OpenAPISchema):
    """Path parameter schema for trust anchor ID."""

    trust_anchor_id = fields.Str(
        required=True,
        metadata={"description": "Trust anchor record identifier"},
    )


class SigningKeyIdMatchSchema(OpenAPISchema):
    """Path parameter schema for signing key ID."""

    signing_key_id = fields.Str(
        required=True,
        metadata={"description": "Signing key record identifier"},
    )


class TrustAnchorQuerySchema(OpenAPISchema):
    """Query string schema for listing trust anchors."""

    doctype = fields.Str(
        required=False,
        metadata={"description": "Filter by doctype", "example": "org.iso.18013.5.1.mDL"},
    )
    purpose = fields.Str(
        required=False,
        metadata={"description": "Filter by purpose: 'iaca' or 'reader_auth'"},
    )


class SigningKeyQuerySchema(OpenAPISchema):
    """Query string schema for listing signing keys."""

    doctype = fields.Str(
        required=False,
        metadata={"description": "Filter by doctype", "example": "org.iso.18013.5.1.mDL"},
    )
    label = fields.Str(
        required=False,
        metadata={"description": "Filter by label"},
    )


class TrustAnchorListSchema(OpenAPISchema):
    """Response schema for trust anchor list."""

    results = fields.List(fields.Nested(TrustAnchorRecordSchema()))


class SigningKeyListSchema(OpenAPISchema):
    """Response schema for signing key list."""

    results = fields.List(fields.Nested(MdocSigningKeyRecordSchema()))


# ---------------------------------------------------------------------------
# Trust anchor routes
# ---------------------------------------------------------------------------


@docs(tags=["mso-mdoc"], summary="Create a new mDoc trust anchor")
@request_schema(TrustAnchorRecordSchema())
@response_schema(TrustAnchorRecordSchema(), 200)
@tenant_authentication
async def create_trust_anchor(request: web.Request):
    """Create and persist a new TrustAnchorRecord."""
    context: AdminRequestContext = request["context"]
    body = await request.json()

    record = TrustAnchorRecord(
        doctype=body.get("doctype"),
        purpose=body.get("purpose", "iaca"),
        label=body.get("label"),
        certificate_pem=body.get("certificate_pem"),
    )

    try:
        async with context.profile.session() as session:
            await record.save(session, reason="Create trust anchor")
    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(record.serialize())


@docs(tags=["mso-mdoc"], summary="List mDoc trust anchors")
@querystring_schema(TrustAnchorQuerySchema())
@response_schema(TrustAnchorListSchema(), 200)
@tenant_authentication
async def list_trust_anchors(request: web.Request):
    """Return all TrustAnchorRecords, optionally filtered."""
    context: AdminRequestContext = request["context"]

    tag_filter = {}
    if "doctype" in request.rel_url.query:
        tag_filter["doctype"] = request.rel_url.query["doctype"]
    if "purpose" in request.rel_url.query:
        tag_filter["purpose"] = request.rel_url.query["purpose"]

    try:
        async with context.profile.session() as session:
            records = await TrustAnchorRecord.query(
                session, tag_filter=tag_filter if tag_filter else None
            )
    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response({"results": [r.serialize() for r in records]})


@docs(tags=["mso-mdoc"], summary="Get a single mDoc trust anchor by ID")
@match_info_schema(TrustAnchorIdMatchSchema())
@response_schema(TrustAnchorRecordSchema(), 200)
@tenant_authentication
async def get_trust_anchor(request: web.Request):
    """Retrieve a single TrustAnchorRecord by ID."""
    context: AdminRequestContext = request["context"]
    trust_anchor_id = request.match_info["trust_anchor_id"]

    try:
        async with context.profile.session() as session:
            record = await TrustAnchorRecord.retrieve_by_id(session, trust_anchor_id)
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err
    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(record.serialize())


@docs(tags=["mso-mdoc"], summary="Delete an mDoc trust anchor")
@match_info_schema(TrustAnchorIdMatchSchema())
@tenant_authentication
async def delete_trust_anchor(request: web.Request):
    """Delete a TrustAnchorRecord by ID."""
    context: AdminRequestContext = request["context"]
    trust_anchor_id = request.match_info["trust_anchor_id"]

    try:
        async with context.profile.session() as session:
            record = await TrustAnchorRecord.retrieve_by_id(session, trust_anchor_id)
            await record.delete_record(session)
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err
    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response({})


# ---------------------------------------------------------------------------
# Signing key routes
# ---------------------------------------------------------------------------


@docs(tags=["mso-mdoc"], summary="Generate a new mDoc signing key")
@request_schema(MdocSigningKeyCreateSchema())
@response_schema(MdocSigningKeyRecordSchema(), 200)
@tenant_authentication
async def create_signing_key(request: web.Request):
    """Generate an EC P-256 key pair and persist a new MdocSigningKeyRecord.

    The private key is generated server-side and never exposed via the API.
    The response includes the derived ``public_key_pem`` so the caller can
    submit it to an IACA for certificate signing.  The certificate can be
    attached later via ``PUT /mso-mdoc/signing-keys/{id}``.
    """
    context: AdminRequestContext = request["context"]
    body = await request.json()

    private_key_pem = generate_ec_p256_key_pem()
    certificate_pem = body.get("certificate_pem")

    if certificate_pem:
        try:
            validate_cert_matches_private_key(private_key_pem, certificate_pem)
        except ValueError as err:
            raise web.HTTPBadRequest(reason=str(err)) from err

    record = MdocSigningKeyRecord(
        doctype=body.get("doctype"),
        label=body.get("label"),
        private_key_pem=private_key_pem,
        certificate_pem=certificate_pem,
    )

    try:
        async with context.profile.session() as session:
            await record.save(session, reason="Generate signing key")
    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(record.serialize())


@docs(
    tags=["mso-mdoc"],
    summary="Import an existing mDoc signing key",
)
@request_schema(MdocSigningKeyImportSchema())
@response_schema(MdocSigningKeyRecordSchema(), 200)
@tenant_authentication
async def import_signing_key(request: web.Request):
    """Import a pre-existing EC signing key and optional certificate.

    Use this for keys already registered with a public trust registry
    (IACA, etc.) that cannot be regenerated.
    """
    context: AdminRequestContext = request["context"]
    body = await request.json()

    private_key_pem = body.get("private_key_pem")
    if not private_key_pem:
        raise web.HTTPBadRequest(reason="private_key_pem is required for import")

    certificate_pem = body.get("certificate_pem")
    if certificate_pem:
        try:
            validate_cert_matches_private_key(private_key_pem, certificate_pem)
        except ValueError as err:
            raise web.HTTPBadRequest(reason=str(err)) from err

    record = MdocSigningKeyRecord(
        doctype=body.get("doctype"),
        label=body.get("label"),
        private_key_pem=private_key_pem,
        certificate_pem=certificate_pem,
    )

    try:
        async with context.profile.session() as session:
            await record.save(session, reason="Import signing key")
    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(record.serialize())


@docs(tags=["mso-mdoc"], summary="Update an mDoc signing key record")
@match_info_schema(SigningKeyIdMatchSchema())
@request_schema(MdocSigningKeyUpdateSchema())
@response_schema(MdocSigningKeyRecordSchema(), 200)
@tenant_authentication
async def update_signing_key(request: web.Request):
    """Update a MdocSigningKeyRecord (attach certificate, change label, etc.).

    If ``certificate_pem`` is provided, the certificate's public key is
    validated against the stored private key to prevent mismatched pairs.
    """
    context: AdminRequestContext = request["context"]
    signing_key_id = request.match_info["signing_key_id"]
    body = await request.json()

    try:
        async with context.profile.session() as session:
            record = await MdocSigningKeyRecord.retrieve_by_id(session, signing_key_id)

            certificate_pem = body.get("certificate_pem")
            if certificate_pem and record.private_key_pem:
                try:
                    validate_cert_matches_private_key(
                        record.private_key_pem, certificate_pem
                    )
                except ValueError as err:
                    raise web.HTTPBadRequest(reason=str(err)) from err
                record.certificate_pem = certificate_pem

            if "doctype" in body:
                record.doctype = body["doctype"]
            if "label" in body:
                record.label = body["label"]

            await record.save(session, reason="Update signing key")
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err
    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(record.serialize())


@docs(tags=["mso-mdoc"], summary="List mDoc signing keys")
@querystring_schema(SigningKeyQuerySchema())
@response_schema(SigningKeyListSchema(), 200)
@tenant_authentication
async def list_signing_keys(request: web.Request):
    """Return all MdocSigningKeyRecords, optionally filtered."""
    context: AdminRequestContext = request["context"]

    tag_filter = {}
    if "doctype" in request.rel_url.query:
        tag_filter["doctype"] = request.rel_url.query["doctype"]
    if "label" in request.rel_url.query:
        tag_filter["label"] = request.rel_url.query["label"]

    try:
        async with context.profile.session() as session:
            records = await MdocSigningKeyRecord.query(
                session, tag_filter=tag_filter if tag_filter else None
            )
    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response({"results": [r.serialize() for r in records]})


@docs(tags=["mso-mdoc"], summary="Get a single mDoc signing key by ID")
@match_info_schema(SigningKeyIdMatchSchema())
@response_schema(MdocSigningKeyRecordSchema(), 200)
@tenant_authentication
async def get_signing_key(request: web.Request):
    """Retrieve a single MdocSigningKeyRecord by ID."""
    context: AdminRequestContext = request["context"]
    signing_key_id = request.match_info["signing_key_id"]

    try:
        async with context.profile.session() as session:
            record = await MdocSigningKeyRecord.retrieve_by_id(session, signing_key_id)
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err
    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(record.serialize())


@docs(tags=["mso-mdoc"], summary="Delete an mDoc signing key")
@match_info_schema(SigningKeyIdMatchSchema())
@tenant_authentication
async def delete_signing_key(request: web.Request):
    """Delete a MdocSigningKeyRecord by ID."""
    context: AdminRequestContext = request["context"]
    signing_key_id = request.match_info["signing_key_id"]

    try:
        async with context.profile.session() as session:
            record = await MdocSigningKeyRecord.retrieve_by_id(session, signing_key_id)
            await record.delete_record(session)
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err
    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response({})


async def register(app: web.Application):
    """Register mso_mdoc trust anchor and signing key routes."""
    app.add_routes(
        [
            # Trust anchor endpoints
            web.post("/mso-mdoc/trust-anchors", create_trust_anchor),
            web.get("/mso-mdoc/trust-anchors", list_trust_anchors),
            web.get("/mso-mdoc/trust-anchors/{trust_anchor_id}", get_trust_anchor),
            web.delete("/mso-mdoc/trust-anchors/{trust_anchor_id}", delete_trust_anchor),
            # Signing key endpoints
            web.post("/mso-mdoc/signing-keys", create_signing_key),
            web.post("/mso-mdoc/signing-keys/import", import_signing_key),
            web.get("/mso-mdoc/signing-keys", list_signing_keys),
            web.get("/mso-mdoc/signing-keys/{signing_key_id}", get_signing_key),
            web.put("/mso-mdoc/signing-keys/{signing_key_id}", update_signing_key),
            web.delete("/mso-mdoc/signing-keys/{signing_key_id}", delete_signing_key),
        ]
    )
