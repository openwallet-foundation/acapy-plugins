"""Crypto module for OID4VCI client."""

from abc import ABC, abstractmethod
import base64
from dataclasses import dataclass
import json
import time
from typing import Generic, TypeVar, Union

from aries_askar import Key

K = TypeVar("K")


class OID4VCICryptoService(ABC, Generic[K]):
    """OpenID Connect for Verifiable Credentials (OID4VC) Crypto Service."""

    @abstractmethod
    async def jwk(self, key: K) -> dict:
        """Return JWK from public key."""

    @abstractmethod
    async def proof_of_possession(self, key: K) -> dict:
        """Return proof of possession over key."""

    @classmethod
    def b64url(cls, value: Union[dict, str, bytes]) -> str:
        """Base64 URL encode a value, without padding."""
        if isinstance(value, dict):
            value = json.dumps(value)
        if isinstance(value, str):
            value = value.encode("utf-8")

        return base64.urlsafe_b64encode(value).rstrip(b"=").decode("utf-8")


@dataclass
class AskarKey:
    """Askar Key."""

    key: Key
    kid: str


class AskarCryptoService(OID4VCICryptoService[AskarKey]):
    """Askar Crypto Service."""

    async def jwk(self, key: AskarKey):
        """Return JWK from public key."""
        return json.loads(key.key.get_jwk_public())

    async def proof_of_possession(self, key: AskarKey, issuer: str, nonce: str):
        """Return proof of possession over key."""
        headers = self.b64url(
            {
                "alg": "EdDSA",
                "typ": "JWT",
                "kid": key.kid,
            }
        )
        payload = self.b64url(
            {
                "aud": issuer,
                "iat": int(time.time()),
                "nonce": nonce,
            }
        )
        signature = self.b64url(
            key.key.sign_message(f"{headers}.{payload}".encode("utf-8"))
        )
        return {"proof_type": "jwt", "jwt": f"{headers}.{payload}.{signature}"}
