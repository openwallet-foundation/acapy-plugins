"""OID4VP request routes for admin API."""

import json
import re
from typing import List
from urllib.parse import quote

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.messaging.models.base import BaseModelError
from acapy_agent.messaging.models.openapi import OpenAPISchema
from acapy_agent.storage.base import BaseStorage, StorageRecord
from acapy_agent.storage.error import StorageError, StorageNotFoundError
from aiohttp import web
from aiohttp_apispec import (
    docs,
    querystring_schema,
    request_schema,
    response_schema,
)
from marshmallow import fields

from ..config import Config
from ..did_utils import retrieve_or_create_did_jwk
from ..models.presentation import (
    OID4VPPresentation,
    OID4VPPresentationSchema,
)
from ..models.request import (
    OID4VPRequest,
    OID4VPRequestSchema,
)


class CreateOID4VPReqResponseSchema(OpenAPISchema):
    """Response schema for creating an OID4VP Request."""

    request_uri = fields.Str(
        required=True,
        metadata={
            "description": "URI for the holder to resolve the request",
        },
    )

    request = fields.Nested(
        OID4VPRequestSchema,
        required=True,
        metadata={"descripton": "The created request"},
    )

    presentation = fields.Nested(
        OID4VPPresentationSchema,
        required=True,
        metadata={"descripton": "The created presentation"},
    )


class CreateOID4VPReqRequestSchema(OpenAPISchema):
    """Request schema for creating an OID4VP Request."""

    pres_def_id = fields.Str(
        required=False,
        metadata={
            "description": "Identifier used to identify presentation definition",
        },
    )

    dcql_query_id = fields.Str(
        required=False,
        metadata={
            "description": "Identifier used to identify DCQL query",
        },
    )

    vp_formats = fields.Dict(
        required=True,
        metadata={
            "description": "Expected presentation formats from the holder",
        },
    )


@docs(
    tags=["oid4vp"],
    summary="Create an OID4VP Request.",
)
@request_schema(CreateOID4VPReqRequestSchema)
@response_schema(CreateOID4VPReqResponseSchema)
async def create_oid4vp_request(request: web.Request):
    """Create an OID4VP Request."""

    context: AdminRequestContext = request["context"]
    body = await request.json()

    async with context.session() as session:
        # Get the DID:JWK that will be used as fallback client_id
        jwk = await retrieve_or_create_did_jwk(session)

        # Use x509 identity (x509_san_dns) when registered; otherwise did:jwk.
        storage = session.inject(BaseStorage)
        try:
            x509_record = await storage.get_record(
                X509_IDENTITY_RECORD_TYPE, X509_IDENTITY_RECORD_ID
            )
            x509_id = json.loads(x509_record.value)
        except StorageNotFoundError:
            x509_id = None

        # OID4VP Final (ID3+): client_id for x509_san_dns scheme uses
        # URI prefix format: "x509_san_dns:{dns_name}".
        # This must match the client_id in the JAR payload.
        if x509_id:
            effective_client_id = f"x509_san_dns:{x509_id['client_id']}"
        else:
            effective_client_id = jwk.did

        if pres_def_id := body.get("pres_def_id"):
            req_record = OID4VPRequest(
                pres_def_id=pres_def_id, vp_formats=body["vp_formats"]
            )
            await req_record.save(session=session)

            pres_record = OID4VPPresentation(
                pres_def_id=pres_def_id,
                state=OID4VPPresentation.REQUEST_CREATED,
                request_id=req_record.request_id,
                client_id=effective_client_id,
            )
            await pres_record.save(session=session)

        elif dcql_query_id := body.get("dcql_query_id"):
            req_record = OID4VPRequest(
                dcql_query_id=dcql_query_id, vp_formats=body["vp_formats"]
            )
            await req_record.save(session=session)

            pres_record = OID4VPPresentation(
                dcql_query_id=dcql_query_id,
                state=OID4VPPresentation.REQUEST_CREATED,
                request_id=req_record.request_id,
                client_id=effective_client_id,
            )
            await pres_record.save(session=session)
        else:
            raise web.HTTPBadRequest(
                reason="One of pres_def_id or dcql_query_id must be provided"
            )

    config = Config.from_settings(context.settings)
    # wallet.id is present on sub-wallet profiles in all multitenant modes;
    # do not gate on multitenant.enabled (absent from sub-wallet settings in
    # single-wallet-askar mode), just read it directly.
    wallet_id = context.profile.settings.get("wallet.id")
    subpath = f"/tenant/{wallet_id}" if wallet_id else ""
    # Use OID4VP_ENDPOINT when available (may differ from OID4VCI endpoint,
    # e.g.served via a separate TLS-terminating proxy for conformance tests).
    oid4vp_base = config.oid4vp_endpoint or config.endpoint
    request_uri = quote(f"{oid4vp_base}{subpath}/oid4vp/request/{req_record._id}")
    # In OID4VP Final spec, client_id_scheme was removed from authorization
    # request query parameters (it was removed in ID3 / draft-28).  The scheme
    # is communicated inside the signed JAR instead.  Do NOT include
    # client_id_scheme as a query parameter.
    full_uri = (
        f"openid://?client_id={quote(effective_client_id)}&request_uri={request_uri}"
    )

    return web.json_response(
        {
            "request_uri": full_uri,
            "request": req_record.serialize(),
            "presentation": pres_record.serialize(),
        }
    )


class OID4VPRequestQuerySchema(OpenAPISchema):
    """Parameters and validators for presentations list query."""

    request_id = fields.UUID(
        required=False,
        metadata={"description": "Filter by request identifier."},
    )
    pres_def_id = fields.Str(
        required=False,
        metadata={"description": "Filter by presentation definition identifier."},
    )
    dcql_query_id = fields.Str(
        required=False,
        metadata={"description": "Filter by DCQL query identifier."},
    )


class OID4VPRequestListSchema(OpenAPISchema):
    """Result schema for an presentations query."""

    results = fields.Nested(
        OID4VPPresentationSchema(),
        many=True,
        metadata={"description": "Presentation Requests"},
    )


@docs(
    tags=["oid4vp"],
    summary="Fetch all OID4VP Requests.",
)
@querystring_schema(OID4VPRequestQuerySchema())
@response_schema(OID4VPRequestListSchema())
async def list_oid4vp_requests(request: web.Request):
    """Request handler for searching requests."""

    context: AdminRequestContext = request["context"]

    try:
        async with context.profile.session() as session:
            if request_id := request.query.get("request_id"):
                record = await OID4VPRequest.retrieve_by_id(session, request_id)
                results = [record.serialize()]
            else:
                filter_ = {
                    attr: value
                    for attr in ("pres_def_id", "dcql_query_id")
                    if (value := request.query.get(attr))
                }
                records = await OID4VPRequest.query(session=session, tag_filter=filter_)
                results = [record.serialize() for record in records]
    except (StorageError, BaseModelError, StorageNotFoundError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err
    return web.json_response({"results": results})


# ---------------------------------------------------------------------------
# X.509 identity admin endpoints
#
# These endpoints manage a single "X.509 identity" record that lets ACA-Py act
# as an OID4VP verifier with client_id_scheme=x509_san_dns.  The record stores
# the DER certificate chain (base64, leaf-first) together with the
# verification method referencing the matching signing key and the DNS name
# used as client_id.
# ---------------------------------------------------------------------------

X509_IDENTITY_RECORD_TYPE = "OID4VP.x509_identity"
X509_IDENTITY_RECORD_ID = "OID4VP.x509_identity"


class RegisterX509IdentitySchema(OpenAPISchema):
    """Request body for registering an X.509 identity."""

    cert_chain_pem = fields.Str(
        required=True,
        metadata={
            "description": (
                "PEM-encoded certificate chain (leaf first, concatenated).  "
                "Each certificate will be stored as a base64-encoded DER value "
                "in the x5c array."
            )
        },
    )
    verification_method = fields.Str(
        required=True,
        metadata={
            "description": (
                'Verification method identifier (e.g. "did:jwk:...#0") that '
                "references the key matching the leaf certificate."
            )
        },
    )
    client_id = fields.Str(
        required=True,
        metadata={
            "description": (
                "DNS name used as client_id in OID4VP requests "
                "(must match the dNSName SAN in the leaf certificate)."
            )
        },
    )


@docs(tags=["oid4vp"], summary="Register X.509 identity for OID4VP requests")
@request_schema(RegisterX509IdentitySchema())
async def register_x509_identity(request: web.Request):
    """Store an X.509 certificate chain for x509_san_dns OID4VP requests."""
    context: AdminRequestContext = request["context"]
    body = await request.json()

    pem: str = body["cert_chain_pem"]
    verification_method: str = body["verification_method"]
    client_id: str = body["client_id"]

    # Parse PEM → list of base64 DER strings (whitespace stripped)
    b64_certs: List[str] = [
        re.sub(r"\s+", "", cert)
        for cert in re.findall(
            r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----",
            pem,
            re.DOTALL,
        )
    ]
    if not b64_certs:
        raise web.HTTPBadRequest(reason="No certificates found in cert_chain_pem")

    value = json.dumps(
        {
            "cert_chain": b64_certs,
            "verification_method": verification_method,
            "client_id": client_id,
        }
    )

    async with context.session() as session:
        storage = session.inject(BaseStorage)
        # replace any existing record
        try:
            existing = await storage.get_record(
                X509_IDENTITY_RECORD_TYPE, X509_IDENTITY_RECORD_ID
            )
            await storage.update_record(existing, value, {})
        except StorageNotFoundError:
            record = StorageRecord(
                type=X509_IDENTITY_RECORD_TYPE,
                value=value,
                id=X509_IDENTITY_RECORD_ID,
            )
            await storage.add_record(record)

    return web.json_response(
        {
            "cert_chain": b64_certs,
            "verification_method": verification_method,
            "client_id": client_id,
        }
    )


@docs(tags=["oid4vp"], summary="Retrieve registered X.509 identity")
async def get_x509_identity(request: web.Request):
    """Return the stored X.509 identity record."""
    context: AdminRequestContext = request["context"]

    async with context.session() as session:
        storage = session.inject(BaseStorage)
        try:
            record = await storage.get_record(
                X509_IDENTITY_RECORD_TYPE, X509_IDENTITY_RECORD_ID
            )
            return web.json_response(json.loads(record.value))
        except StorageNotFoundError:
            raise web.HTTPNotFound(reason="No X.509 identity registered")


@docs(tags=["oid4vp"], summary="Delete registered X.509 identity")
async def delete_x509_identity(request: web.Request):
    """Remove the stored X.509 identity record."""
    context: AdminRequestContext = request["context"]

    async with context.session() as session:
        storage = session.inject(BaseStorage)
        try:
            record = await storage.get_record(
                X509_IDENTITY_RECORD_TYPE, X509_IDENTITY_RECORD_ID
            )
            await storage.delete_record(record)
        except StorageNotFoundError:
            raise web.HTTPNotFound(reason="No X.509 identity registered")

    return web.json_response({"deleted": True})
