"""Dev seeding script: creates a tenant and three test clients.

Usage examples:
  - python -m admin.dev_seed --uid tenant-dev --name "Dev Tenant"

Outputs client credentials (print-only; shared secrets are shown once).
"""

import argparse
import asyncio
import secrets
from typing import Any

from authlib.jose import JsonWebKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from admin.config import settings
from admin.schemas.client import ClientIn
from admin.services.tenant_service import TenantService
from core.db.session import DatabaseSessionManager


def _gen_es256_keypair() -> tuple[str, dict[str, Any]]:
    prv = ec.generate_private_key(ec.SECP256R1())
    private_pem = prv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = (
        prv.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )
    public_jwk = JsonWebKey.import_key(public_pem).as_dict()  # type: ignore
    return private_pem, public_jwk  # type: ignore


async def _ensure_tenant(svc: TenantService, uid: str, name: str):
    try:
        repo = svc.repo
        row = await repo.get_by_uid(uid)
        if row is None:
            raise Exception("tenant_not_found")
        return row
    except Exception as ex:
        raise ex


async def main() -> None:
    """Seed dev tenant and clients."""
    parser = argparse.ArgumentParser(description="Seed dev tenant and clients")
    parser.add_argument("--uid", required=True, help="Tenant uid")
    parser.add_argument(
        "--name", required=False, default="Dev Tenant", help="Tenant name"
    )
    args = parser.parse_args()

    dbm = DatabaseSessionManager(search_path="admin")
    dbm.init(settings.DB_URL)
    try:
        async with dbm.session() as session:
            svc = TenantService(session)
            tenant = await _ensure_tenant(svc, args.uid, args.name)

            # 1) private_key_jwt (ES256)
            pk_client_id = f"dev-pkjwt-{secrets.token_hex(4)}"
            private_pem, public_jwk = _gen_es256_keypair()
            jwks = {"keys": [public_jwk]}
            pk_payload = ClientIn(
                client_id=pk_client_id,
                client_auth_method="private_key_jwt",
                client_auth_signing_alg="ES256",
                jwks=jwks,
            )
            await svc.create_client(tenant.uid, pk_payload)

            # 2) shared_bearer (HS256)
            sb_client_id = f"dev-shared-{secrets.token_hex(4)}"
            sb_secret = secrets.token_urlsafe(32)
            sb_payload = ClientIn(
                client_id=sb_client_id,
                client_auth_method="shared_bearer",
                client_auth_signing_alg="HS256",
                client_secret=sb_secret,
            )
            await svc.create_client(tenant.uid, sb_payload)

            # 3) client_secret_basic (PBKDF2 stored)
            cs_client_id = f"dev-basic-{secrets.token_hex(4)}"
            cs_secret = secrets.token_urlsafe(24)
            cs_payload = ClientIn(
                client_id=cs_client_id,
                client_auth_method="client_secret_basic",
                client_secret=cs_secret,
            )
            await svc.create_client(tenant.uid, cs_payload)

            print("Seed complete:\n")
            print("Tenant:", tenant.uid)
            print("\nprivate_key_jwt client:")
            print("  client_id:", pk_client_id)
            print("  signing_alg: ES256")
            print("  jwks (public):", jwks)
            print("  private_key_pem (keep secret):\n", private_pem)

            print("\nshared_bearer client:")
            print("  client_id:", sb_client_id)
            print("  signing_alg: HS256")
            print("  shared_secret (keep secret):", sb_secret)

            print("\nclient_secret_basic client:")
            print("  client_id:", cs_client_id)
            print("  client_secret (keep secret):", cs_secret)
    finally:
        await dbm.close()


if __name__ == "__main__":
    asyncio.run(main())
