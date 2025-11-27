"""Utilities for shared functions."""

import base64
import hashlib
import json
from dataclasses import dataclass

import jcs
from multiformats import multibase, multihash

from acapy_agent.vc.data_integrity.manager import DataIntegrityManager
from acapy_agent.vc.data_integrity.models.options import DataIntegrityProofOptions
from acapy_agent.wallet.keys.manager import MultikeyManager

WITNESS_CONNECTION_ALIAS_SUFFIX = "@witness"
ALIAS_PURPOSES = {
    "witnessConnection": "@witness",
    "nextKey": "@nextKey",
    "updateKey": "@updateKey",
    "witnessKey": "@witnessKey",
    "innkeeperKey": "@innkeeper",
}


@dataclass(frozen=True)
class ParsedWebVHDID:
    """Parsed WebVH DID components."""

    did: str
    method: str  # "webvh"
    scid: str
    domain: str
    namespace: str
    identifier: str

    def __str__(self) -> str:
        """Return the full DID string."""
        return self.did

    @property
    def namespace_identifier(self) -> tuple[str, str]:
        """Get namespace and identifier as a tuple."""
        return (self.namespace, self.identifier)


@dataclass(frozen=True)
class ParsedDIDKey:
    """Parsed did:key DID components."""

    did: str
    method: str  # "key"
    key: str

    def __str__(self) -> str:
        """Return the full DID string."""
        return self.did


def url_to_domain(url: str):
    """Get server domain."""
    domain = url.split("://")[-1]
    if "%3A" in domain:
        domain = domain.replace("%3A", ":")
    return domain


def create_alias(identifier: str, purpose: str):
    """Get static alias."""
    return f"webvh:{identifier}{ALIAS_PURPOSES[purpose]}"


def decode_invitation(invitation_url: str):
    """Decode an oob invitation url."""
    encoded_invitation = invitation_url.split("oob=")[-1]
    return json.loads(base64.urlsafe_b64decode(f"{encoded_invitation}===").decode())


def key_hash(key):
    """Return key hash."""
    return multibase.encode(multihash.digest(key.encode(), "sha2-256"), "base58btc")[1:]


def multikey_to_jwk(multikey):
    """Derive JWK."""
    # TODO, support other key types than ed25519
    jwk = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": base64.urlsafe_b64encode(multibase.decode(multikey)[2:])
        .decode()
        .rstrip("="),
    }
    thumbprint = (
        base64.urlsafe_b64encode(hashlib.sha256(jcs.canonicalize(jwk)).digest())
        .decode()
        .rstrip("=")
    )
    return jwk, thumbprint


def all_are_not_none(*args):
    """Check if all arguments are not None."""
    return all(v is not None for v in args)


def parse_webvh(did: str) -> ParsedWebVHDID:
    """Parse a WebVH DID into its components.

    Expected format: did:webvh:{scid}:{domain}:{namespace}:{identifier}

    Args:
        did: The DID string to parse

    Returns:
        ParsedWebVHDID object with parsed components

    Raises:
        ValueError: If the DID format is invalid
    """
    parts = did.split(":")
    if len(parts) < 6:
        raise ValueError(
            "Invalid WebVH DID format. "
            f"Expected 'did:webvh:{{scid}}:{{domain}}:{{namespace}}:{{identifier}}', "
            f"got: {did}"
        )

    if parts[0] != "did":
        raise ValueError(f"Invalid DID format. Must start with 'did:', got: {did}")

    if parts[1] != "webvh":
        raise ValueError(f"Invalid DID method. Expected 'webvh', got: {parts[1]}")

    return ParsedWebVHDID(
        did=did,
        method=parts[1],
        scid=parts[2],
        domain=parts[3],
        namespace=parts[4],
        identifier=parts[5],
    )


def parse_did_key(did: str) -> ParsedDIDKey:
    """Parse a did:key DID into its components.

    Expected format: did:key:{key}

    Args:
        did: The DID string to parse

    Returns:
        ParsedDIDKey object with parsed components

    Raises:
        ValueError: If the DID format is invalid
    """
    parts = did.split(":")
    if len(parts) < 3:
        raise ValueError(
            f"Invalid did:key format. Expected 'did:key:{{key}}', got: {did}"
        )

    if parts[0] != "did":
        raise ValueError(f"Invalid DID format. Must start with 'did:', got: {did}")

    if parts[1] != "key":
        raise ValueError(f"Invalid DID method. Expected 'key', got: {parts[1]}")

    # The key is everything after "did:key:"
    key = ":".join(parts[2:])

    return ParsedDIDKey(did=did, method=parts[1], key=key)


def parse_did(did: str) -> ParsedWebVHDID | ParsedDIDKey:
    """Parse a DID, automatically detecting the format.

    Args:
        did: The DID string to parse

    Returns:
        ParsedWebVHDID or ParsedDIDKey object depending on DID method

    Raises:
        ValueError: If the DID format is invalid or unsupported
    """
    parts = did.split(":")
    if len(parts) < 2:
        raise ValueError(f"Invalid DID format: {did}")

    method = parts[1]

    if method == "webvh":
        return parse_webvh(did)
    elif method == "key":
        return parse_did_key(did)
    else:
        raise ValueError(
            f"Unsupported DID method: {method}. Supported methods: webvh, key"
        )


def extract_key_from_did_key(did: str) -> str:
    """Extract the key from a did:key DID.

    This is a convenience function for extracting just the key portion.

    Args:
        did: The did:key string

    Returns:
        The key portion of the DID

    Raises:
        ValueError: If the DID format is invalid
    """
    parsed = parse_did_key(did)
    return parsed.key


def get_namespace_and_identifier_from_did(did: str):
    """Extract namespace and identifier from a DID.

    This function is kept for backward compatibility.
    Consider using parse_webvh() directly for new code.
    """
    parsed = parse_webvh(did)
    return parsed.namespace_identifier


async def create_key(profile, kid=None) -> str:
    """Create key shortcut."""
    async with profile.session() as session:
        key = await MultikeyManager(session).create(alg="ed25519", kid=kid)
    return key.get("multikey")


async def find_key(profile, kid) -> str | None:
    """Find key given a key id shortcut."""
    try:
        async with profile.session() as session:
            key = await MultikeyManager(session).from_kid(
                kid=kid,
            )
        return key.get("multikey")
    except AttributeError:
        return None


async def find_multikey(profile, multikey) -> str:
    """Find multikey shortcut."""
    async with profile.session() as session:
        key = await MultikeyManager(session).from_multikey(multikey)
    return key.get("multikey")


async def bind_key(profile, multikey, kid) -> str:
    """Bind key to a given key id shortcut."""
    async with profile.session() as session:
        key = await MultikeyManager(session).update(
            kid=kid,
            multikey=multikey,
        )
    return key.get("multikey")


async def unbind_key(profile, multikey, kid):
    """Unbind key id from key shortcut."""
    async with profile.session() as session:
        await MultikeyManager(session).unbind_key_id(
            kid=kid,
            multikey=multikey,
        )


async def add_proof(
    profile, document, verification_method, proof_purpose="assertionMethod"
) -> dict:
    """Add data integrity proof to document shortcut."""
    async with profile.session() as session:
        signed_document = await DataIntegrityManager(session).add_proof(
            document,
            DataIntegrityProofOptions(
                type="DataIntegrityProof",
                cryptosuite="eddsa-jcs-2022",
                proof_purpose=proof_purpose,
                verification_method=verification_method,
            ),
        )
    return signed_document


async def verify_proof(profile, document) -> bool:
    """Verify data integrity proof shortcut."""
    async with profile.session() as session:
        verified = await DataIntegrityManager(session).verify_proof(document)
    return verified


def validate_webvh_did(did: str, domain: str, namespace: str, identifier: str) -> bool:
    """Validate a did against the components.

    Args:
        did: The DID string to validate
        domain: Expected domain
        namespace: Expected namespace
        identifier: Expected identifier

    Returns:
        True if the DID matches the components, False otherwise
    """
    try:
        parsed = parse_webvh(did)
        return (
            parsed.domain == domain
            and parsed.namespace == namespace
            and parsed.identifier == identifier
        )
    except ValueError:
        return False


def validate_did(did: str, domain: str, namespace: str, identifier: str) -> bool:
    """Validate a did against the components.

    This function is kept for backward compatibility.
    Consider using validate_webvh_did() directly for new code.
    """
    return validate_webvh_did(did, domain, namespace, identifier)


def format_witness_ready_message(
    witness_id: str, invitation_url: str = None, server_url: str = None
) -> str:
    """Format a witness ready message for display and logging.

    Args:
        witness_id: The witness DID identifier
        invitation_url: Optional invitation URL (defaults to "<not available>")
        server_url: Optional server URL for building server invitation link

    Returns:
        Formatted message string
    """
    from acapy_agent.config.banner import _Banner
    from urllib.parse import urlparse, parse_qs

    # Transform invitation URL to didcomm:// format if it contains oob parameter
    invitation_display = invitation_url if invitation_url else "<not available>"
    if invitation_url and "oob=" in invitation_url:
        try:
            parsed_url = urlparse(invitation_url)
            query_params = parse_qs(parsed_url.query)
            if "oob" in query_params:
                oob_value = query_params["oob"][0]
                invitation_display = f"didcomm://?oob={oob_value}"
        except Exception:
            # If transformation fails, use original URL
            invitation_display = invitation_url

    # Build server invitation URL if server_url is provided
    server_invitation_display = "<not available>"
    if server_url:
        parsed_key = parse_did_key(witness_id)
        witness_key = parsed_key.key
        server_invitation_display = f"{server_url}/api/invitations?_oobid={witness_key}"

    # Build banner using Banner class directly (not as context manager)
    # so we can access the lines before the final border is added
    banner = _Banner(border=":", length=80)
    banner.add_border()
    banner.title("Witness Service")
    banner.spacer()
    # Add "Witness ID" section with dashes
    banner.hr("-")
    banner.centered("Witness ID")
    banner.hr("-")
    banner.spacer()
    banner.print(witness_id)
    banner.spacer()
    # Add "Invitation" section with dashes
    banner.hr("-")
    banner.centered("Invitation")
    banner.hr("-")
    banner.spacer()
    banner.print(invitation_display)
    banner.spacer()
    # Add "Server Invitation" section with dashes
    banner.hr("-")
    banner.centered("Server Invitation")
    banner.hr("-")
    banner.spacer()
    banner.print(server_invitation_display)
    banner.spacer()
    banner.add_border()

    # Join all lines with newlines
    banner_text = "\n".join(banner.lines)

    return banner_text
