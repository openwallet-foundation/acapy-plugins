"""OIDC discovery and JWKS with conditional introspection."""

import ipaddress

from fastapi import Request

from core.consts import OAuth2GrantType, SUPPORTED_SIGNING_ALGS
from core.utils.logging import get_logger
from tenant.config import settings
from tenant.deps import get_tenant_ctx, get_tenant_jwks

logger = get_logger(__name__)

_TRUSTED_NETWORKS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
for _cidr in getattr(settings, "TRUSTED_NETWORKS", []):
    if _cidr and isinstance(_cidr, str) and _cidr.strip():
        try:
            _TRUSTED_NETWORKS.append(ipaddress.ip_network(_cidr.strip()))
        except ValueError:
            logger.warning("Invalid CIDR in TRUSTED_NETWORKS, skipping: %s", _cidr)


def is_internal_request(request: Request) -> bool:
    """Return True if client IP is inside any configured CIDR in TRUSTED_NETWORKS."""
    host = getattr(request.client, "host", None)
    if not host:
        return False
    try:
        ip_obj = ipaddress.ip_address(host)
    except ValueError:
        return False
    return any(ip_obj in net for net in _TRUSTED_NETWORKS)


async def build_oauth_auth_server(uid: str, request: Request) -> dict:
    """Build OIDC discovery for a tenant."""
    # Verify tenant exists (triggers fetch/cache from Admin API)
    await get_tenant_ctx(uid, "db")

    base_url = settings.ISSUER_BASE_URL + f"/tenants/{uid}"
    well_known_base_url = settings.ISSUER_BASE_URL + "/.well-known"

    doc = {
        "issuer": base_url,
        "token_endpoint": f"{base_url}/token",
        "response_types_supported": [],
        "token_endpoint_auth_methods_supported": ["none"],
        "token_endpoint_auth_signing_alg_values_supported": list(SUPPORTED_SIGNING_ALGS),
        "grant_types_supported": [
            OAuth2GrantType.PRE_AUTH_CODE,
            OAuth2GrantType.REFRESH_TOKEN,
        ],
        "authorization_details_types_supported": ["openid_credential"],
        "pre-authorized_grant_anonymous_access_supported": True,
        "jwks_uri": f"{well_known_base_url}/jwks.json/tenants/{uid}",
    }

    if settings.ATTESTATION_ENABLED:
        if settings.ATTESTATION_REQUIRED:
            doc["token_endpoint_auth_methods_supported"] = ["attest_jwt_client_auth"]
            doc["pre-authorized_grant_anonymous_access_supported"] = False
        else:
            doc["token_endpoint_auth_methods_supported"].append("attest_jwt_client_auth")
        doc["client_attestation_signing_alg_values_supported"] = list(
            SUPPORTED_SIGNING_ALGS
        )
        doc["client_attestation_pop_signing_alg_values_supported"] = list(
            SUPPORTED_SIGNING_ALGS
        )

    if is_internal_request(request):
        doc["introspection_endpoint"] = f"{base_url}/introspect"
        doc["introspection_endpoint_auth_methods_supported"] = [
            "client_secret_basic",
            "private_key_jwt",
        ]
        doc["introspection_endpoint_auth_signing_alg_values_supported"] = list(
            SUPPORTED_SIGNING_ALGS
        )

    return doc


async def load_tenant_jwks(uid: str) -> dict:
    """Fetch tenant JWKS (RFC 7517)."""
    return await get_tenant_jwks(uid)
