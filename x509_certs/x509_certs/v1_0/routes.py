"""X.509 admin routes."""

from datetime import datetime, timezone

from acapy_agent.admin.decorators.auth import tenant_authentication
from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.messaging.models.openapi import OpenAPISchema
from acapy_agent.storage.error import StorageNotFoundError
from acapy_agent.wallet.base import BaseWallet
from acapy_agent.wallet.error import WalletError, WalletNotFoundError
from acapy_agent.wallet.keys.manager import (
    MultikeyManager,
    MultikeyManagerError,
    multikey_to_verkey,
)
from aiohttp import web
from aiohttp_apispec import (
    docs,
    match_info_schema,
    querystring_schema,
    request_schema,
    response_schema,
)
from marshmallow import fields, validate

from .certs import (
    X509Error,
    check_chain_order,
    describe,
    load_pem_chain,
    load_x5c,
    public_key_multikey,
    to_pem,
    to_x5c,
)
from .models import (
    ANCHOR_PURPOSE_FOR,
    ANCHOR_PURPOSES,
    CERTIFICATE_PURPOSES,
    X509CertificateRecord,
    X509CertificateRecordSchema,
    X509TrustAnchorRecord,
    X509TrustAnchorRecordSchema,
)
from .signing import build_csr, build_self_signed
from .verify import check_ca, verify_chain

TAG = "x509"
MULTIKEY_EXAMPLE = "zDnaeZv4cPZ9zVfMvxWdjnXc1hFXY9LYM894FyZpVsGHnx3oG"


class X509SubjectSchema(OpenAPISchema):
    """Certificate subject fields."""

    common_name = fields.Str(required=False, metadata={"example": "Example Issuer"})
    organization = fields.Str(required=False, metadata={"example": "Example Org"})
    organizational_unit = fields.Str(required=False)
    locality = fields.Str(required=False)
    state = fields.Str(required=False)
    country = fields.Str(required=False, metadata={"example": "CA"})


class X509CsrRequestSchema(OpenAPISchema):
    """Request to build a CSR for a wallet key."""

    multikey = fields.Str(required=True, metadata={"example": MULTIKEY_EXAMPLE})
    subject = fields.Nested(X509SubjectSchema(), required=True)
    dns_names = fields.List(fields.Str(), required=False)
    uris = fields.List(fields.Str(), required=False)


class X509CsrResponseSchema(OpenAPISchema):
    """CSR response."""

    csr = fields.Str(metadata={"description": "PEM-encoded CSR"})


class X509SelfSignedRequestSchema(X509CsrRequestSchema):
    """Request to create a self-signed certificate for a wallet key."""

    purpose = fields.Str(required=True, validate=validate.OneOf(CERTIFICATE_PURPOSES))
    days = fields.Int(
        required=False, load_default=365, validate=validate.Range(min=1, max=3650)
    )


class X509CertificateImportSchema(OpenAPISchema):
    """Request to import a certificate chain."""

    chain = fields.Str(
        required=True,
        metadata={
            "description": (
                "PEM certificates, leaf first; the leaf key must be in the wallet"
            )
        },
    )
    purpose = fields.Str(required=True, validate=validate.OneOf(CERTIFICATE_PURPOSES))


class X509CertificateQuerySchema(OpenAPISchema):
    """Certificate list filters."""

    multikey = fields.Str(required=False)
    kid = fields.Str(required=False)
    purpose = fields.Str(required=False, validate=validate.OneOf(CERTIFICATE_PURPOSES))
    subject = fields.Str(
        required=False, metadata={"description": "Exact RFC 4514 subject"}
    )
    valid_at = fields.DateTime(required=False)


class X509CertificateListSchema(OpenAPISchema):
    """Certificate list."""

    results = fields.List(fields.Nested(X509CertificateRecordSchema()))


class X509CertIdMatchSchema(OpenAPISchema):
    """Path parameter: certificate id."""

    cert_id = fields.Str(required=True)


class X509TrustAnchorImportSchema(OpenAPISchema):
    """Request to import a trust anchor."""

    certificate_pem = fields.Str(
        required=True, metadata={"description": "One PEM CA certificate"}
    )
    purpose = fields.Str(required=True, validate=validate.OneOf(ANCHOR_PURPOSES))
    label = fields.Str(required=False)


class X509TrustAnchorQuerySchema(OpenAPISchema):
    """Trust anchor list filters."""

    purpose = fields.Str(required=False, validate=validate.OneOf(ANCHOR_PURPOSES))
    subject = fields.Str(
        required=False, metadata={"description": "Exact RFC 4514 subject"}
    )


class X509TrustAnchorListSchema(OpenAPISchema):
    """Trust anchor list."""

    results = fields.List(fields.Nested(X509TrustAnchorRecordSchema()))


class X509AnchorIdMatchSchema(OpenAPISchema):
    """Path parameter: trust anchor id."""

    anchor_id = fields.Str(required=True)


class X509VerifyRequestSchema(OpenAPISchema):
    """Request to verify a chain."""

    chain = fields.Str(
        required=False, metadata={"description": "PEM certificates, leaf first"}
    )
    x5c = fields.List(
        fields.Str(),
        required=False,
        metadata={"description": "Standard base64 DER certificates, leaf first"},
    )
    purpose = fields.Str(required=True, validate=validate.OneOf(CERTIFICATE_PURPOSES))
    at = fields.DateTime(required=False, metadata={"description": "Defaults to now"})


class X509VerifyResponseSchema(OpenAPISchema):
    """Verification result."""

    verified = fields.Bool()
    anchor_id = fields.Str(required=False)
    error = fields.Str(required=False)


async def _key_type_for(session, multikey: str):
    """Verkey and key type of a wallet key; 400 if the multikey is not a wallet key."""
    try:
        verkey = multikey_to_verkey(multikey)
        return verkey, (await session.inject(BaseWallet).get_signing_key(verkey)).key_type
    except (MultikeyManagerError, ValueError) as err:
        raise web.HTTPBadRequest(reason=f"Invalid multikey: {err}") from err
    except WalletNotFoundError:
        raise web.HTTPBadRequest(reason="Key is not in the wallet") from None


def _parse_time(value):
    if value is None:
        return datetime.now(timezone.utc)
    parsed = datetime.fromisoformat(value) if isinstance(value, str) else value
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _certificate_record(certs, multikey: str, purpose: str) -> X509CertificateRecord:
    return X509CertificateRecord(
        multikey=multikey, purpose=purpose, x5c=to_x5c(certs), **describe(certs[0])
    )


@docs(tags=[TAG], summary="Create a CSR signed by a wallet key")
@request_schema(X509CsrRequestSchema())
@response_schema(X509CsrResponseSchema(), 200)
@tenant_authentication
async def create_csr(request: web.Request):
    """Build a CSR for a wallet key."""
    context: AdminRequestContext = request["context"]
    body = await request.json()
    async with context.session() as session:
        verkey, key_type = await _key_type_for(session, body["multikey"])
        try:
            csr = await build_csr(
                session.inject(BaseWallet),
                verkey,
                key_type,
                body["subject"],
                body.get("dns_names"),
                body.get("uris"),
            )
        except (X509Error, WalletError) as err:
            raise web.HTTPBadRequest(reason=str(err)) from err
    return web.json_response({"csr": csr})


@docs(tags=[TAG], summary="Import a certificate chain for a wallet key")
@request_schema(X509CertificateImportSchema())
@response_schema(X509CertificateRecordSchema(), 200)
@tenant_authentication
async def import_certificate(request: web.Request):
    """Store a chain whose leaf key is in the wallet."""
    context: AdminRequestContext = request["context"]
    body = await request.json()
    try:
        certs = load_pem_chain(body["chain"])
        check_chain_order(certs)
        multikey = public_key_multikey(certs[0])
    except X509Error as err:
        raise web.HTTPBadRequest(reason=str(err)) from err

    record = _certificate_record(certs, multikey, body["purpose"])
    async with context.session() as session:
        await _key_type_for(session, multikey)
        await record.save(session, reason="Import X.509 certificate")
    return web.json_response(record.serialize())


@docs(tags=[TAG], summary="Create a self-signed certificate for a wallet key (demo only)")
@request_schema(X509SelfSignedRequestSchema())
@response_schema(X509CertificateRecordSchema(), 200)
@tenant_authentication
async def create_self_signed(request: web.Request):
    """Create and store a self-signed certificate, if enabled."""
    context: AdminRequestContext = request["context"]
    plugin_config = context.settings.get("plugin_config") or {}
    if (plugin_config.get("x509") or {}).get("allow_self_signed") is not True:
        raise web.HTTPForbidden(reason="Self-signed certificates are disabled")

    body = await request.json()
    async with context.session() as session:
        verkey, key_type = await _key_type_for(session, body["multikey"])
        try:
            cert = await build_self_signed(
                session.inject(BaseWallet),
                verkey,
                key_type,
                body["subject"],
                body.get("days", 365),
                body.get("dns_names"),
                body.get("uris"),
            )
        except (X509Error, WalletError) as err:
            raise web.HTTPBadRequest(reason=str(err)) from err
        record = _certificate_record([cert], body["multikey"], body["purpose"])
        await record.save(session, reason="Create self-signed X.509 certificate")
    return web.json_response(record.serialize())


@docs(tags=[TAG], summary="List certificates")
@querystring_schema(X509CertificateQuerySchema())
@response_schema(X509CertificateListSchema(), 200)
@tenant_authentication
async def list_certificates(request: web.Request):
    """List certificates, optionally filtered."""
    context: AdminRequestContext = request["context"]
    query = request.query
    tag_filter = {k: query[k] for k in ("multikey", "purpose", "subject") if k in query}
    async with context.session() as session:
        if "kid" in query:
            key_info = await MultikeyManager(session).from_kid(query["kid"])
            if not key_info:
                return web.json_response({"results": []})
            if tag_filter.get("multikey", key_info["multikey"]) != key_info["multikey"]:
                return web.json_response({"results": []})
            tag_filter["multikey"] = key_info["multikey"]
        records = await X509CertificateRecord.query(session, tag_filter or None)

    if "valid_at" in query:
        at = _parse_time(query["valid_at"])
        records = [
            r
            for r in records
            if datetime.fromisoformat(r.not_before)
            <= at
            <= datetime.fromisoformat(r.not_after)
        ]
    return web.json_response({"results": [r.serialize() for r in records]})


@docs(tags=[TAG], summary="Get a certificate")
@match_info_schema(X509CertIdMatchSchema())
@response_schema(X509CertificateRecordSchema(), 200)
@tenant_authentication
async def get_certificate(request: web.Request):
    """Fetch one certificate record."""
    context: AdminRequestContext = request["context"]
    try:
        async with context.session() as session:
            record = await X509CertificateRecord.retrieve_by_id(
                session, request.match_info["cert_id"]
            )
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err
    return web.json_response(record.serialize())


@docs(tags=[TAG], summary="Delete a certificate")
@match_info_schema(X509CertIdMatchSchema())
@tenant_authentication
async def delete_certificate(request: web.Request):
    """Delete one certificate record."""
    context: AdminRequestContext = request["context"]
    try:
        async with context.session() as session:
            record = await X509CertificateRecord.retrieve_by_id(
                session, request.match_info["cert_id"]
            )
            await record.delete_record(session)
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err
    return web.json_response({})


@docs(tags=[TAG], summary="Import a trust anchor")
@request_schema(X509TrustAnchorImportSchema())
@response_schema(X509TrustAnchorRecordSchema(), 200)
@tenant_authentication
async def import_trust_anchor(request: web.Request):
    """Store one CA certificate as a trust anchor."""
    context: AdminRequestContext = request["context"]
    body = await request.json()
    try:
        certs = load_pem_chain(body["certificate_pem"])
        if len(certs) != 1:
            raise X509Error("Import one certificate per trust anchor")
        check_ca(certs[0], "Trust anchor")
    except X509Error as err:
        raise web.HTTPBadRequest(reason=str(err)) from err

    details = describe(certs[0])
    record = X509TrustAnchorRecord(
        purpose=body["purpose"],
        certificate_pem=to_pem(certs[0]),
        subject=details["subject"],
        not_after=details["not_after"],
        label=body.get("label"),
    )
    async with context.session() as session:
        await record.save(session, reason="Import X.509 trust anchor")
    return web.json_response(record.serialize())


@docs(tags=[TAG], summary="List trust anchors")
@querystring_schema(X509TrustAnchorQuerySchema())
@response_schema(X509TrustAnchorListSchema(), 200)
@tenant_authentication
async def list_trust_anchors(request: web.Request):
    """List trust anchors, optionally filtered."""
    context: AdminRequestContext = request["context"]
    tag_filter = {
        k: request.query[k] for k in ("purpose", "subject") if k in request.query
    }
    async with context.session() as session:
        records = await X509TrustAnchorRecord.query(session, tag_filter or None)
    return web.json_response({"results": [r.serialize() for r in records]})


@docs(tags=[TAG], summary="Get a trust anchor")
@match_info_schema(X509AnchorIdMatchSchema())
@response_schema(X509TrustAnchorRecordSchema(), 200)
@tenant_authentication
async def get_trust_anchor(request: web.Request):
    """Fetch one trust anchor."""
    context: AdminRequestContext = request["context"]
    try:
        async with context.session() as session:
            record = await X509TrustAnchorRecord.retrieve_by_id(
                session, request.match_info["anchor_id"]
            )
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err
    return web.json_response(record.serialize())


@docs(tags=[TAG], summary="Delete a trust anchor")
@match_info_schema(X509AnchorIdMatchSchema())
@tenant_authentication
async def delete_trust_anchor(request: web.Request):
    """Delete one trust anchor."""
    context: AdminRequestContext = request["context"]
    try:
        async with context.session() as session:
            record = await X509TrustAnchorRecord.retrieve_by_id(
                session, request.match_info["anchor_id"]
            )
            await record.delete_record(session)
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err
    return web.json_response({})


@docs(tags=[TAG], summary="Verify a chain against the trust anchors for its purpose")
@request_schema(X509VerifyRequestSchema())
@response_schema(X509VerifyResponseSchema(), 200)
@tenant_authentication
async def verify(request: web.Request):
    """Verify a leaf-first chain against anchors of the matching purpose."""
    context: AdminRequestContext = request["context"]
    body = await request.json()
    if ("chain" in body) == ("x5c" in body):
        raise web.HTTPBadRequest(reason="Provide exactly one of chain or x5c")
    try:
        certs = (
            load_pem_chain(body["chain"]) if "chain" in body else load_x5c(body["x5c"])
        )
        at = _parse_time(body.get("at"))
    except (X509Error, ValueError) as err:
        raise web.HTTPBadRequest(reason=str(err)) from err

    async with context.session() as session:
        records = await X509TrustAnchorRecord.query(
            session, {"purpose": ANCHOR_PURPOSE_FOR[body["purpose"]]}
        )
    anchors = [(r, load_pem_chain(r.certificate_pem)[0]) for r in records]
    try:
        anchor = verify_chain(certs, [cert for _, cert in anchors], at)
    except X509Error as err:
        return web.json_response({"verified": False, "error": str(err)})
    anchor_id = next(r.anchor_id for r, cert in anchors if cert is anchor)
    return web.json_response({"verified": True, "anchor_id": anchor_id})


async def register(app: web.Application):
    """Register routes."""
    app.add_routes(
        [
            web.post("/x509/csr", create_csr),
            web.post("/x509/certificates", import_certificate),
            web.get("/x509/certificates", list_certificates, allow_head=False),
            web.post("/x509/certificates/self-signed", create_self_signed),
            web.get("/x509/certificates/{cert_id}", get_certificate, allow_head=False),
            web.delete("/x509/certificates/{cert_id}", delete_certificate),
            web.post("/x509/trust-anchors", import_trust_anchor),
            web.get("/x509/trust-anchors", list_trust_anchors, allow_head=False),
            web.get(
                "/x509/trust-anchors/{anchor_id}", get_trust_anchor, allow_head=False
            ),
            web.delete("/x509/trust-anchors/{anchor_id}", delete_trust_anchor),
            web.post("/x509/verify", verify),
        ]
    )


def post_process_routes(app: web.Application):
    """Add the x509 tag description to the swagger document."""
    app._state["swagger_dict"].setdefault("tags", []).append(
        {"name": TAG, "description": "X.509 certificates and trust anchors"}
    )
