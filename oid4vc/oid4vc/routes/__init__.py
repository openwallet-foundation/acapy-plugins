"""Admin API Routes."""

from aiohttp import web

from .exchange import (
    ExchangeRecordQuerySchema,
    ExchangeRecordListSchema,
    ExchangeRecordCreateRequestSchema,
    ExchangeRecordIDMatchSchema,
    ExchangeRefreshIDMatchSchema,
    list_exchange_records,
    create_exchange,
    exchange_create,
    credential_refresh,
    get_exchange_by_id,
    exchange_delete,
)
from .credential_offer import (
    CredOfferQuerySchema,
    CredOfferGrantSchema,
    CredOfferSchema,
    CredOfferResponseSchemaVal,
    CredOfferResponseSchemaRef,
    _create_pre_auth_code,
    _parse_cred_offer,
    get_cred_offer,
    get_cred_offer_by_ref,
)
from .supported_credential import (
    SupportedCredCreateRequestSchema,
    SupportedCredentialQuerySchema,
    SupportedCredentialListSchema,
    SupportedCredentialMatchSchema,
    supported_cred_is_unique,
    supported_credential_list,
    get_supported_credential_by_id,
    supported_credential_remove,
)
from .vp_request import (
    CreateOID4VPReqResponseSchema,
    CreateOID4VPReqRequestSchema,
    OID4VPRequestQuerySchema,
    OID4VPRequestListSchema,
    create_oid4vp_request,
    list_oid4vp_requests,
)
from .vp_dcql import (
    CreateDCQLQueryRequestSchema,
    CreateDCQLQueryResponseSchema,
    DCQLQueriesQuerySchema,
    DCQLQueryListSchema,
    DCQLQueryIDMatchSchema,
    GetDCQLQueryResponseSchema,
    create_dcql_query,
    list_dcql_queries,
    get_dcql_query_by_id,
    dcql_query_remove,
)
from .vp_pres_def import (
    CreateOID4VPPresDefRequestSchema,
    CreateOID4VPPresDefResponseSchema,
    PresDefIDMatchSchema,
    UpdateOID4VPPresDefRequestSchema,
    UpdateOID4VPPresDefResponseSchema,
    OID4VPPresDefQuerySchema,
    OID4VPPresDefListSchema,
    create_oid4vp_pres_def,
    update_oid4vp_pres_def,
    list_oid4vp_pres_defs,
    get_oid4vp_pres_def_by_id,
    oid4vp_pres_def_remove,
)
from .vp_presentation import (
    PresRequestIDMatchSchema,
    OID4VPPresQuerySchema,
    OID4VPPresListSchema,
    PresentationIDMatchSchema,
    GetOID4VPPresResponseSchema,
    get_oid4vp_request_by_id,
    list_oid4vp_presentations,
    get_oid4vp_pres_by_id,
    oid4vp_pres_remove,
)
from .did_jwk import (
    CreateDIDJWKRequestSchema,
    CreateDIDJWKResponseSchema,
    create_did_jwk,
)
from .helpers import (
    IssuerConfigInfoSchema,
    get_issuer_config,
    upsert_issuer_config,
)

VCI_SPEC_URI = "https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html"
VP_SPEC_URI = "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html"

__all__ = [
    "CredOfferGrantSchema",
    "CredOfferQuerySchema",
    "CredOfferResponseSchemaRef",
    "CredOfferResponseSchemaVal",
    "CredOfferSchema",
    "CreateDCQLQueryRequestSchema",
    "CreateDCQLQueryResponseSchema",
    "CreateDIDJWKRequestSchema",
    "CreateDIDJWKResponseSchema",
    "CreateOID4VPPresDefRequestSchema",
    "CreateOID4VPPresDefResponseSchema",
    "CreateOID4VPReqRequestSchema",
    "CreateOID4VPReqResponseSchema",
    "DCQLQueriesQuerySchema",
    "DCQLQueryIDMatchSchema",
    "DCQLQueryListSchema",
    "ExchangeRecordCreateRequestSchema",
    "ExchangeRecordIDMatchSchema",
    "ExchangeRecordListSchema",
    "ExchangeRecordQuerySchema",
    "ExchangeRefreshIDMatchSchema",
    "GetDCQLQueryResponseSchema",
    "GetOID4VPPresResponseSchema",
    "IssuerConfigInfoSchema",
    "OID4VPPresDefListSchema",
    "OID4VPPresDefQuerySchema",
    "OID4VPPresListSchema",
    "OID4VPPresQuerySchema",
    "OID4VPRequestListSchema",
    "OID4VPRequestQuerySchema",
    "PresDefIDMatchSchema",
    "PresRequestIDMatchSchema",
    "PresentationIDMatchSchema",
    "SupportedCredCreateRequestSchema",
    "SupportedCredentialListSchema",
    "SupportedCredentialMatchSchema",
    "SupportedCredentialQuerySchema",
    "UpdateOID4VPPresDefRequestSchema",
    "UpdateOID4VPPresDefResponseSchema",
    "_create_pre_auth_code",
    "_parse_cred_offer",
    "create_dcql_query",
    "create_did_jwk",
    "create_exchange",
    "create_oid4vp_pres_def",
    "create_oid4vp_request",
    "credential_refresh",
    "dcql_query_remove",
    "exchange_create",
    "exchange_delete",
    "get_cred_offer",
    "get_cred_offer_by_ref",
    "get_dcql_query_by_id",
    "get_exchange_by_id",
    "get_issuer_config",
    "get_oid4vp_pres_by_id",
    "get_oid4vp_pres_def_by_id",
    "get_oid4vp_request_by_id",
    "get_supported_credential_by_id",
    "list_dcql_queries",
    "list_exchange_records",
    "list_oid4vp_pres_defs",
    "list_oid4vp_presentations",
    "list_oid4vp_requests",
    "oid4vp_pres_def_remove",
    "oid4vp_pres_remove",
    "post_process_routes",
    "register",
    "supported_cred_is_unique",
    "supported_credential_list",
    "supported_credential_remove",
    "update_oid4vp_pres_def",
    "upsert_issuer_config",
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
            web.delete(
                "/oid4vci/credential-supported/records/{supported_cred_id}",
                supported_credential_remove,
            ),
            web.post("/oid4vp/request", create_oid4vp_request),
            web.get("/oid4vp/requests", list_oid4vp_requests),
            web.get("/oid4vp/request/{request_id}", get_oid4vp_request_by_id),
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
            web.get("/oid4vci/issuer/configuration", get_issuer_config, allow_head=False),
            web.put("/oid4vci/issuer/configuration", upsert_issuer_config),
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
