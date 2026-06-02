"""OpenID Connect 4 Verifiable Credential Issuance Client."""

import json
from dataclasses import dataclass
from typing import Dict, List, Literal, Optional, Union, Any
from urllib.parse import parse_qsl, urlparse

from aiohttp import ClientSession

from .crypto import AskarCryptoService, AskarKey
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
    credential_configuration_ids: List[str]
    credentials: List[str]
    authorization_code: Optional[dict] = None
    pre_authorized_code: Optional[CredentialGrantPreAuth] = None

    @classmethod
    def from_dict(cls, value: dict):
        """Parse from dict."""
        offer = value["offer"]
        cred_config_ids = offer.get("credential_configuration_ids") or []
        credentials = offer.get("credentials") or []

        return cls(
            offer["credential_issuer"],
            cred_config_ids,
            credentials,
            offer.get("grants", {}).get("authorization_code"),
            CredentialGrantPreAuth.from_grants(offer.get("grants", {})),
        )


@dataclass
class IssuerMetadata:
    """Issuer Metadata."""

    credential_endpoint: str
    token_endpoint: str
    credential_configurations_supported: dict[str, Any]
    nonce_endpoint: Optional[str] = None


@dataclass
class TokenParams:
    """Token Parameters."""

    access_token: str
    nonce: Optional[str] = None


class OpenID4VCIClient:
    """OpenID Connect 4 Verifiable Credential Issuance Client."""

    def __init__(self, key: Optional[AskarKey] = None):
        """Initialize the client."""
        self.did_to_key: Dict[str, AskarKey] = {}

    def generate_did(self, key_type: Literal["ed25519", "secp256k1"]) -> str:
        """Generate a DID."""
        did, key = generate(key_type)
        self.did_to_key[did] = key
        return did

    async def get_issuer_metadata(self, issuer_url: str):
        """Get the issuer metadata."""
        async with ClientSession() as session:
            async with session.get(
                issuer_url + "/.well-known/openid-credential-issuer"
            ) as resp:
                metadata = await resp.json()

        token_endpoint = metadata.get("token_endpoint") or issuer_url + "/token"
        authorization_server = metadata.get("authorization_server")
        if authorization_server:
            token_endpoint = authorization_server + "/token"

        return IssuerMetadata(
            metadata["credential_endpoint"],
            token_endpoint,
            metadata["credential_configurations_supported"],
            nonce_endpoint=metadata.get("nonce_endpoint"),
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

        # OID4VCI 1.0: c_nonce is only present in the token response when the
        # issuer does NOT publish a Nonce Endpoint. Otherwise it's fetched
        # per-request from POST /nonce (see request_credential).
        return TokenParams(
            token["access_token"],
            token.get("c_nonce"),
        )

    async def fetch_nonce(self, nonce_endpoint: str) -> str:
        """Fetch a fresh nonce from the Nonce Endpoint (OID4VCI 1.0 §7)."""
        async with ClientSession() as session:
            async with session.post(nonce_endpoint) as resp:
                if resp.status != 200:
                    raise ValueError(
                        f"Error fetching nonce: {resp.status} {await resp.text()}"
                    )
                body = await resp.json()
        return body["c_nonce"]

    async def request_credential(
        self,
        holder_did: str,
        offer: CredentialOffer,
        metadata: IssuerMetadata,
        token: TokenParams,
    ) -> dict:
        """Request a credential."""
        if not offer.pre_authorized_code:
            raise ValueError("No pre-authorized code in offer")

        key = self.did_to_key.get(holder_did)
        if not key:
            raise ValueError(f"No key for DID {holder_did}")

        credential_configuration_id = (
            offer.credential_configuration_ids[0]
            if offer.credential_configuration_ids
            else next(iter(metadata.credential_configurations_supported), None)
        )
        if credential_configuration_id is None:
            raise ValueError("No credential_configuration_id in offer or metadata")

        nonce = token.nonce
        if nonce is None:
            if not metadata.nonce_endpoint:
                raise ValueError(
                    "Token response has no c_nonce and issuer does not publish "
                    "nonce_endpoint"
                )
            nonce = await self.fetch_nonce(metadata.nonce_endpoint)

        proofs = await crypto.proof_of_possession(
            key, offer.credential_issuer, nonce
        )
        if isinstance(proofs.get("jwt"), str):
            proofs["jwt"] = [proofs["jwt"]]

        request = {
            "credential_configuration_id": credential_configuration_id,
            "proofs": proofs,
        }
        if offer.credentials:
            request["type"] = offer.credentials

        async with ClientSession() as session:
            async with session.post(
                metadata.credential_endpoint,
                headers={"Authorization": f"Bearer {token.access_token}"},
                json=request,
            ) as resp:
                if resp.status != 200:
                    raise ValueError(f"Error requesting credential: {await resp.text()}")
                credential = await resp.json()

        return credential

    async def receive_offer(self, offer_in: Union[str, dict], holder_did: str):
        """Receive an offer."""
        if isinstance(offer_in, str):
            parsed = dict(parse_qsl(urlparse(offer_in).query))
            offer_in = json.loads(parsed["credential_offer"])
            assert isinstance(offer_in, dict)

        offer = CredentialOffer.from_dict(offer_in)
        metadata = await self.get_issuer_metadata(offer.credential_issuer)
        token = await self.request_token(offer, metadata)
        response = await self.request_credential(holder_did, offer, metadata, token)
        return response
