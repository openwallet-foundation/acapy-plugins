"""MsoVerifier helper class to verify a mso."""

import logging
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pycose.keys import CoseKey
from pycose.messages import Sign1Message
import cryptography
import cbor2


LOGGER = logging.getLogger(__name__)


class MsoVerifier:
    """MsoVerifier helper class to verify a mso."""

    def __init__(self, data: cbor2.CBORTag) -> None:
        """Create a new MsoParser instance."""
        if isinstance(data, list):
            data = cbor2.dumps(cbor2.CBORTag(18, value=data))

        self.object: Sign1Message = Sign1Message.decode(data)
        self.public_key = None
        self.x509_certificates: list = []

    @property
    def raw_public_keys(self) -> bytes:
        """Extract public key from x509 certificates."""
        _mixed_heads = list(self.object.phdr.items()) + list(self.object.uhdr.items())
        for h, v in _mixed_heads:
            if h.identifier == 33:
                return list(self.object.uhdr.values())

    def attest_public_key(self) -> None:
        """Asstest public key."""
        LOGGER.warning(
            "TODO: in next releases. "
            "The certificate is to be considered as untrusted, this release "
            "doesn't validate x.509 certificate chain. See next releases and "
            "python certvalidator or cryptography for that."
        )

    def load_public_key(self) -> None:
        """Load the public key from the x509 certificate."""
        self.attest_public_key()

        for i in self.raw_public_keys:
            self.x509_certificates.append(cryptography.x509.load_der_x509_certificate(i))

        self.public_key = self.x509_certificates[0].public_key()
        pem_public = self.public_key.public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        ).decode()
        self.object.key = CoseKey.from_pem_public_key(pem_public)

    def verify_signature(self) -> bool:
        """Verify the signature."""
        self.load_public_key()

        return self.object.verify_signature()
