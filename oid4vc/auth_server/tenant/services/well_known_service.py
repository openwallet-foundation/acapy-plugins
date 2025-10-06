"""OIDC discovery and JWKS with conditional introspection."""

import ipaddress

from fastapi import Request

from core.consts import OAuth2GrantType
from tenant.config import settings
from tenant.deps import get_tenant_jwks

try:
    _TRUSTED_NETWORKS = [
        ipaddress.ip_network(cidr.strip())
        for cidr in getattr(settings, "TRUSTED_NETWORKS", [])
        if cidr and cidr.strip()
    ]
except ValueError:
    _TRUSTED_NETWORKS = []


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


def build_openid_configuration(uid: str, request: Request) -> dict:
    """Build OIDC discovery for a tenant."""
    base_url = settings.ISSUER_BASE_URL + f"/tenants/{uid}"

    doc = {
        "issuer": base_url,
        "token_endpoint": f"{base_url}/token",
        "token_endpoint_auth_methods_supported": ["none"],
        "grant_types_supported": [
            OAuth2GrantType.PRE_AUTH_CODE,
            OAuth2GrantType.REFRESH_TOKEN,
        ],
        "authorization_details_types_supported": ["openid_credential"],
        "jwks_uri": f"{base_url}/.well-known/jwks.json",
    }

    if is_internal_request(request):
        doc["introspection_endpoint"] = f"{base_url}/introspect"
        doc["introspection_endpoint_auth_methods_supported"] = [
            "private_key_jwt",
            "client_secret_basic",
            "shared_bearer",
        ]
        doc["introspection_endpoint_auth_signing_alg_values_supported"] = [
            "ES256",
            "HS256",
        ]

    return doc


async def load_tenant_jwks(uid: str) -> dict:
    """Fetch tenant JWKS (RFC 7517)."""
    return await get_tenant_jwks(uid)
