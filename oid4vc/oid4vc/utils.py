"""Utility functions for OID4VCI plugin."""

import argparse
import json
from types import SimpleNamespace
from typing import Dict

from acapy_agent.core.profile import Profile
from acapy_agent.messaging.util import datetime_now
from acapy_agent.wallet.util import b58_to_bytes, bytes_to_b64, str_to_b64
from oid4vc.config import Config
from oid4vc.jwt import jwt_sign

EXPIRES_IN = 300


def get_tenant_subpath(profile: Profile, tenant_prefix: str = "/tenants") -> str:
    """Get the tenant path for the current wallet, if any."""

    wallet_id = (
        profile.settings.get("wallet.id")
        if profile.settings.get("multitenant.enabled")
        else None
    )
    tenant_subpath = f"{tenant_prefix}/{wallet_id}" if wallet_id else ""
    return tenant_subpath


def verkey_to_jwk(verkey: str) -> Dict:
    """Convert a base58 verkey (Ed25519) to a JWK dict."""

    key_bytes = b58_to_bytes(verkey)
    x = bytes_to_b64(key_bytes)
    jwk = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": x,
    }
    return jwk


async def get_auth_header(
    profile: Profile, config: Config, issuer: str, audience: str
) -> str:
    """Create a JWT auth token for the given type and verification method."""

    if not config.auth_server_client:
        raise ValueError("auth_server_client setting is required.")

    auth_client = json.loads(
        config.auth_server_client, object_hook=lambda d: SimpleNamespace(**d)
    )

    if auth_client.auth_type == "client_secret_basic":
        cred = f"{auth_client.client_id}:{auth_client.client_secret}"
        b64_cred = str_to_b64(cred)
        auth_header = f"Basic {b64_cred}"

    elif auth_client.auth_type == "private_key_jwt":
        utcnow = datetime_now()
        payload = {
            "iss": f"{issuer}",
            "sub": f"{auth_client.client_id}",
            "aud": f"{audience}",
            "iat": int(utcnow.timestamp()),
            "exp": int(utcnow.timestamp()) + EXPIRES_IN,
        }
        headers = {}
        token = await jwt_sign(
            profile,
            headers,
            payload,
            did=getattr(auth_client, "did", None),
            verification_method=getattr(auth_client, "verification_method", None),
        )
        auth_header = f"Bearer {token}"

    else:
        auth_header = ""

    return auth_header


if __name__ == "__main__":
    """Run as script to convert base58 verkey to JWK."""
    parser = argparse.ArgumentParser(description="Convert base58 verkey to JWK.")
    parser.add_argument("verkey", help="Base58-encoded Ed25519 public key")
    args = parser.parse_args()

    jwk = verkey_to_jwk(args.verkey)
    jwks = {"keys": [jwk]}
    print(json.dumps(jwks))
