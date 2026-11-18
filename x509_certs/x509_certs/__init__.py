"""X.509 certificates for ACA-Py wallet keys, and trust anchors for chain verification."""

import logging

from acapy_agent.config.injection_context import InjectionContext

from .certs import X509Error, embedded_x5c, pem_chain, select_certificate
from .models import (
    ANCHOR_PURPOSE_FOR,
    ANCHOR_PURPOSES,
    CERTIFICATE_PURPOSES,
    X509CertificateRecord,
    X509TrustAnchorRecord,
)

LOGGER = logging.getLogger(__name__)

__all__ = [
    "ANCHOR_PURPOSE_FOR",
    "ANCHOR_PURPOSES",
    "CERTIFICATE_PURPOSES",
    "X509CertificateRecord",
    "X509Error",
    "X509TrustAnchorRecord",
    "embedded_x5c",
    "pem_chain",
    "select_certificate",
]


async def setup(context: InjectionContext):
    """Set up the X.509 plugin."""
    LOGGER.info("Setting up x509_certs plugin")
