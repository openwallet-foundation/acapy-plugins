"""OpenID Connect 4 Verifiable Credential Issuance Client."""


from dataclasses import dataclass
import json
from typing import List, Optional, Union
from urllib.parse import parse_qsl, urlparse

from aiohttp import ClientSession

from .crypto import AskarKey, AskarCryptoService
from .did import generate

PRE_AUTH_GRANT = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
crypto = AskarCryptoService()


@dataclass
class CredentialGrantPreAuth:
    """Credential Grant Pre-Auth."""

    code: str
    user_pin_required: Optional[bool] = None

    @classmethod
    def from_grants(cls, value: dict) -> Optional["CredentialGrantPreAuth"]:
        """Parse from grants object."""
        if PRE_AUTH_GRANT not in value:
            return None

        pre_auth = value[PRE_AUTH_GRANT]
        return cls(
            pre_auth["pre-authorized_code"],
            pre_auth.get("user_pin_required"),
        )


@dataclass
class CredentialOffer:
    """Credential Offer."""

    credential_issuer: str
    credentials: List[str]
    authorization_code: Optional[dict] = None
    pre_authorized_code: Optional[CredentialGrantPreAuth] = None

    @classmethod
    def from_dict(cls, value: dict):
        """Parse from dict."""
        return cls(
            value["credential_issuer"],
            value["credentials"],
            value.get("grants", {}).get("authorization_code"),
            CredentialGrantPreAuth.from_grants(value.get("grants", {})),
        )


@dataclass
class IssuerMetadata:
    """Issuer Metadata."""

    credential_endpoint: str
    token_endpoint: str
    credentials_supported: List[dict]


@dataclass
class TokenParams:
    """Token Parameters."""

    access_token: str
    nonce: str


class OpenID4VCIClient:
    """OpenID Connect 4 Verifiable Credential Issuance Client."""

    def __init__(self, key: Optional[AskarKey] = None):
        """Initialize the client."""
        if not key:
            did, key = generate()

        self.key = key

    async def get_issuer_metadata(self, issuer_url: str):
        """Get the issuer metadata."""
        async with ClientSession() as session:
            async with session.get(
                issuer_url + "/.well-known/openid-credential-issuer"
            ) as resp:
                metadata = await resp.json()

        token_endpoint = issuer_url + "/token"
        authorization_server = metadata.get("authorization_server")
        if authorization_server:
            token_endpoint = authorization_server + "/token"

        return IssuerMetadata(
            metadata["credential_endpoint"],
            token_endpoint,
            metadata["credentials_supported"],
        )

    async def request_token(self, offer: CredentialOffer, metadata: IssuerMetadata):
        """Request a token."""
        if not offer.pre_authorized_code:
            raise ValueError("No pre-authorized code in offer")

        async with ClientSession() as session:
            async with session.post(
                metadata.token_endpoint,
                data={
                    "grant_type": PRE_AUTH_GRANT,
                    "pre-authorized_code": offer.pre_authorized_code.code,
                },
            ) as resp:
                token = await resp.json()
        return TokenParams(
            token["access_token"],
            token["c_nonce"],
        )

    async def request_credential(
        self, offer: CredentialOffer, metadata: IssuerMetadata, token: TokenParams
    ) -> dict:
        """Request a credential."""
        if not offer.pre_authorized_code:
            raise ValueError("No pre-authorized code in offer")

        request = {
            "format": "jwt_vc_json",
            "types": ["VerifiableCredential"] + offer.credentials,
            "proof": await crypto.proof_of_possession(
                self.key, offer.credential_issuer, token.nonce
            ),
        }
        async with ClientSession() as session:
            async with session.post(
                metadata.credential_endpoint,
                headers={"Authorization": f"Bearer {token.access_token}"},
                json=request,
            ) as resp:
                if resp.status != 200:
                    raise ValueError(
                        f"Error requesting credential: {await resp.text()}"
                    )
                credential = await resp.json()

        return credential

    async def receive_offer(self, offer_in: Union[str, dict]):
        """Receive an offer."""
        if isinstance(offer_in, str):
            parsed = dict(parse_qsl(urlparse(offer_in).netloc))
            offer_in = json.loads(parsed["credential_offer"])
            assert isinstance(offer_in, dict)

        offer = CredentialOffer.from_dict(offer_in)
        metadata = await self.get_issuer_metadata(offer.credential_issuer)
        token = await self.request_token(offer, metadata)
        response = await self.request_credential(offer, metadata, token)
        return response
