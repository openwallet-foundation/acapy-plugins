"""CSRs and self-signed certificates signed by a wallet key."""

import asyncio
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from acapy_agent.wallet.base import BaseWallet
from acapy_agent.wallet.key_type import P256, KeyType
from acapy_agent.wallet.util import b58_to_bytes
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.x509.oid import NameOID

from .certs import X509Error

SUBJECT_FIELDS = {
    "common_name": NameOID.COMMON_NAME,
    "organization": NameOID.ORGANIZATION_NAME,
    "organizational_unit": NameOID.ORGANIZATIONAL_UNIT_NAME,
    "locality": NameOID.LOCALITY_NAME,
    "state": NameOID.STATE_OR_PROVINCE_NAME,
    "country": NameOID.COUNTRY_NAME,
}


class WalletBackedPrivateKey(ec.EllipticCurvePrivateKey):
    """P-256 private key whose signatures come from `wallet.sign_message`.

    `cryptography` builders call `sign()` synchronously, so callers run the
    builder in a worker thread and `sign()` schedules the wallet call on the
    captured event loop.
    """

    def __init__(self, wallet: BaseWallet, verkey: str, loop: asyncio.AbstractEventLoop):
        """Wrap a wallet P-256 key."""
        self._wallet = wallet
        self._verkey = verkey
        self._loop = loop
        self._public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), b58_to_bytes(verkey)
        )

    @property
    def curve(self) -> ec.EllipticCurve:
        """Key curve."""
        return self._public_key.curve

    @property
    def key_size(self) -> int:
        """Key size in bits."""
        return self._public_key.key_size

    def public_key(self) -> ec.EllipticCurvePublicKey:
        """Matching public key."""
        return self._public_key

    def sign(self, data: bytes, signature_algorithm) -> bytes:
        """Sign through the wallet and return a DER ECDSA signature."""
        raw = asyncio.run_coroutine_threadsafe(
            self._wallet.sign_message(data, self._verkey), self._loop
        ).result()
        half = len(raw) // 2
        return utils.encode_dss_signature(
            int.from_bytes(raw[:half], "big"), int.from_bytes(raw[half:], "big")
        )

    def exchange(self, algorithm, peer_public_key):
        """Not supported."""
        raise UnsupportedAlgorithm("ECDH is not supported")

    def private_numbers(self):
        """Not supported."""
        raise UnsupportedAlgorithm("Private key material is not accessible")

    def private_bytes(self, encoding, format, encryption_algorithm):
        """Not supported."""
        raise UnsupportedAlgorithm("Private key material is not accessible")

    def __copy__(self) -> "WalletBackedPrivateKey":
        """Return self; the wallet key cannot be copied."""
        return self

    def __deepcopy__(self, memo) -> "WalletBackedPrivateKey":
        """Return self; the wallet key cannot be copied."""
        return self


def build_name(subject: dict) -> x509.Name:
    """Build an X.509 name from subject fields."""
    unknown = set(subject) - set(SUBJECT_FIELDS)
    if unknown:
        raise X509Error(f"Unknown subject fields: {sorted(unknown)}")
    try:
        attrs = [
            x509.NameAttribute(oid, subject[field])
            for field, oid in SUBJECT_FIELDS.items()
            if subject.get(field)
        ]
    except ValueError as err:
        raise X509Error(f"Invalid subject: {err}") from err
    if not attrs:
        raise X509Error("Subject must have at least one field")
    return x509.Name(attrs)


def _san(dns_names: List[str], uris: List[str]) -> Optional[x509.SubjectAlternativeName]:
    try:
        names = [x509.DNSName(n) for n in dns_names] + [
            x509.UniformResourceIdentifier(u) for u in uris
        ]
    except ValueError as err:
        raise X509Error(f"Invalid subject alternative name: {err}") from err
    return x509.SubjectAlternativeName(names) if names else None


def _check_key_type(key_type: KeyType):
    if key_type != P256:
        raise X509Error(f"Only p256 keys are supported, not {key_type.key_type}")


async def build_csr(
    wallet: BaseWallet,
    verkey: str,
    key_type: KeyType,
    subject: dict,
    dns_names: Optional[List[str]] = None,
    uris: Optional[List[str]] = None,
) -> str:
    """PEM CSR for the wallet key, signed by that key."""
    _check_key_type(key_type)
    key = WalletBackedPrivateKey(wallet, verkey, asyncio.get_running_loop())
    builder = x509.CertificateSigningRequestBuilder().subject_name(build_name(subject))
    if san := _san(dns_names or [], uris or []):
        builder = builder.add_extension(san, critical=False)
    csr = await asyncio.to_thread(builder.sign, key, hashes.SHA256())
    return csr.public_bytes(serialization.Encoding.PEM).decode()


async def build_self_signed(
    wallet: BaseWallet,
    verkey: str,
    key_type: KeyType,
    subject: dict,
    days: int,
    dns_names: Optional[List[str]] = None,
    uris: Optional[List[str]] = None,
) -> x509.Certificate:
    """Self-signed leaf certificate for the wallet key."""
    _check_key_type(key_type)
    key = WalletBackedPrivateKey(wallet, verkey, asyncio.get_running_loop())
    name = build_name(subject)
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    )
    if san := _san(dns_names or [], uris or []):
        builder = builder.add_extension(san, critical=False)
    return await asyncio.to_thread(builder.sign, key, hashes.SHA256())
