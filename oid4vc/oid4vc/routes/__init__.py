"""OID4VC admin routes package.

This package contains the admin API routes for OID4VCI and OID4VP protocols,
organized into logical submodules:

- exchange: OID4VCI exchange record CRUD operations
- credential_offer: Credential offer generation endpoints
- supported_credential: Supported credential configuration CRUD
- vp_request: OID4VP request creation and listing
- vp_dcql: DCQL query CRUD operations
- vp_pres_def: Presentation definition CRUD operations
- vp_presentation: Presentation CRUD operations
- did_jwk: DID:JWK creation endpoint
"""

from aiohttp import web

from .constants import VCI_SPEC_URI, VP_SPEC_URI

# Import all handlers for route registration
from .credential_offer import (
    CredOfferQuerySchema,
    CredOfferResponseSchemaRef,
    CredOfferResponseSchemaVal,
    get_cred_offer,
    get_cred_offer_by_ref,
)
from .did_jwk import create_did_jwk
from .exchange import (
    create_exchange,
    credential_refresh,
    exchange_create,
    exchange_delete,
    get_exchange_by_id,
    list_exchange_records,
)
from .issuer_config import get_issuer_configuration, put_issuer_configuration
from .supported_credential import (
    SupportedCredentialMatchSchema,
    get_supported_credential_by_id,
    supported_credential_list,
    supported_credential_remove,
)
from ..utils import supported_cred_is_unique
from .vp_dcql import (
    create_dcql_query,
    dcql_query_remove,
    get_dcql_query_by_id,
    list_dcql_queries,
)
from .vp_pres_def import (
    create_oid4vp_pres_def,
    get_oid4vp_pres_def_by_id,
    get_oid4vp_request_by_id,
    list_oid4vp_pres_defs,
    oid4vp_pres_def_remove,
    update_oid4vp_pres_def,
)
from .vp_presentation import (
    get_oid4vp_pres_by_id,
    list_oid4vp_presentations,
    oid4vp_pres_remove,
)
from .vp_request import (
    create_oid4vp_request,
    delete_x509_identity,
    get_x509_identity,
    list_oid4vp_requests,
    register_x509_identity,
)

# Public API for backward compatibility
__all__ = [
    # Credential offer
    "CredOfferQuerySchema",
    "CredOfferResponseSchemaVal",
    "CredOfferResponseSchemaRef",
    "get_cred_offer",
    "get_cred_offer_by_ref",
    # Exchange
    "list_exchange_records",
    "exchange_create",
    "create_exchange",
    "credential_refresh",
    "get_exchange_by_id",
    "exchange_delete",
    # Supported credential
    "SupportedCredentialMatchSchema",
    "supported_cred_is_unique",
    "supported_credential_list",
    "get_supported_credential_by_id",
    "supported_credential_remove",
    # VP request
    "create_oid4vp_request",
    "list_oid4vp_requests",
    # X.509 identity
    "register_x509_identity",
    "get_x509_identity",
    "delete_x509_identity",
    # DCQL
    "create_dcql_query",
    "list_dcql_queries",
    "get_dcql_query_by_id",
    "dcql_query_remove",
    # Pres def
    "create_oid4vp_pres_def",
    "update_oid4vp_pres_def",
    "get_oid4vp_request_by_id",
    "list_oid4vp_pres_defs",
    "get_oid4vp_pres_def_by_id",
    "oid4vp_pres_def_remove",
    # Presentation
    "list_oid4vp_presentations",
    "get_oid4vp_pres_by_id",
    "oid4vp_pres_remove",
    # DID JWK
    "create_did_jwk",
    # Issuer configuration
    "get_issuer_configuration",
    "put_issuer_configuration",
    # Registration
    "register",
    "post_process_routes",
]


async def register(app: web.Application):
    """Register routes."""
    app.add_routes(
        [
            web.get("/oid4vci/credential-offer", get_cred_offer, allow_head=False),
            web.get(
                "/oid4vci/credential-offer-by-ref",
                get_cred_offer_by_ref,
                allow_head=False,
            ),
            web.patch("/oid4vci/credential-refresh/{refresh_id}", credential_refresh),
            web.get(
                "/oid4vci/exchange/records",
                list_exchange_records,
                allow_head=False,
            ),
            web.post("/oid4vci/exchange/create", exchange_create),
            web.get(
                "/oid4vci/exchange/records/{exchange_id}",
                get_exchange_by_id,
                allow_head=False,
            ),
            web.delete("/oid4vci/exchange/records/{exchange_id}", exchange_delete),
            web.get(
                "/oid4vci/credential-supported/records",
                supported_credential_list,
                allow_head=False,
            ),
            web.get(
                "/oid4vci/credential-supported/records/{supported_cred_id}",
                get_supported_credential_by_id,
                allow_head=False,
            ),
            web.post("/oid4vp/request", create_oid4vp_request),
            web.get("/oid4vp/requests", list_oid4vp_requests),
            web.get("/oid4vp/request/{request_id}", get_oid4vp_request_by_id),
            web.post("/oid4vp/x509-identity", register_x509_identity),
            web.get("/oid4vp/x509-identity", get_x509_identity, allow_head=False),
            web.delete("/oid4vp/x509-identity", delete_x509_identity),
            web.post("/oid4vp/presentation-definition", create_oid4vp_pres_def),
            web.get("/oid4vp/presentation-definitions", list_oid4vp_pres_defs),
            web.get(
                "/oid4vp/presentation-definition/{pres_def_id}",
                get_oid4vp_pres_def_by_id,
            ),
            web.put(
                "/oid4vp/presentation-definition/{pres_def_id}", update_oid4vp_pres_def
            ),
            web.delete(
                "/oid4vp/presentation-definition/{pres_def_id}", oid4vp_pres_def_remove
            ),
            web.get("/oid4vp/presentations", list_oid4vp_presentations),
            web.get("/oid4vp/presentation/{presentation_id}", get_oid4vp_pres_by_id),
            web.delete("/oid4vp/presentation/{presentation_id}", oid4vp_pres_remove),
            web.post("/oid4vp/dcql/queries", create_dcql_query),
            web.get("/oid4vp/dcql/queries", list_dcql_queries),
            web.get("/oid4vp/dcql/query/{dcql_query_id}", get_dcql_query_by_id),
            web.delete("/oid4vp/dcql/query/{dcql_query_id}", dcql_query_remove),
            web.post("/did/jwk/create", create_did_jwk),
            web.get(
                "/oid4vci/issuer/configuration",
                get_issuer_configuration,
                allow_head=False,
            ),
            web.put("/oid4vci/issuer/configuration", put_issuer_configuration),
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
            "description": "OpenID for VC Issuance",
            "externalDocs": {"description": "Specification", "url": VCI_SPEC_URI},
        }
    )
    app._state["swagger_dict"]["tags"].append(
        {
            "name": "oid4vp",
            "description": "OpenID for VP",
            "externalDocs": {"description": "Specification", "url": VP_SPEC_URI},
        }
    )
