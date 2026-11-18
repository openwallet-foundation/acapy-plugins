from datetime import timedelta

import pytest
from acapy_agent.wallet.base import BaseWallet
from acapy_agent.wallet.key_type import ED25519
from acapy_agent.wallet.keys.manager import multikey_to_verkey
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from x509_certs.certs import (
    X509Error,
    check_chain_order,
    describe,
    embedded_x5c,
    is_self_signed,
    load_pem_chain,
    load_x5c,
    public_key_multikey,
    select_certificate,
    to_pem,
    to_x5c,
)
from x509_certs.models import X509CertificateRecord
from x509_certs.signing import build_csr, build_self_signed
from x509_certs.verify import verify_chain

from .conftest import NOW, Pki, wallet_public_key


def test_load_pem_chain_rejects_garbage():
    with pytest.raises(X509Error):
        load_pem_chain("not a certificate")


def test_pem_and_x5c_round_trip(pki: Pki):
    certs = [pki.intermediate, pki.root]
    assert load_pem_chain("".join(to_pem(c) for c in certs)) == certs
    assert load_x5c(to_x5c(certs)) == certs


def test_check_chain_order(pki: Pki):
    check_chain_order([pki.intermediate, pki.root])
    with pytest.raises(X509Error, match="not issued by"):
        check_chain_order([pki.root, pki.intermediate])


def test_public_key_multikey_matches_wallet_key(pki: Pki, multikey):
    assert public_key_multikey(pki.leaf(wallet_public_key(multikey))) == multikey


def test_public_key_multikey_rejects_other_curves(pki: Pki):
    p384 = ec.generate_private_key(ec.SECP384R1()).public_key()
    with pytest.raises(X509Error, match="P-256 or Ed25519"):
        public_key_multikey(pki.leaf(p384))


def test_embedded_x5c_drops_self_signed_root(pki: Pki, multikey):
    leaf = pki.leaf(wallet_public_key(multikey))

    def record(certs):
        return X509CertificateRecord(
            multikey=multikey,
            purpose="sd_jwt_vc_issuer",
            x5c=to_x5c(certs),
            **describe(leaf),
        )

    assert embedded_x5c(record([leaf, pki.intermediate, pki.root])) == to_x5c(
        [leaf, pki.intermediate]
    )
    assert embedded_x5c(record([leaf, pki.intermediate])) == to_x5c(
        [leaf, pki.intermediate]
    )
    assert embedded_x5c(record([pki.root])) == to_x5c([pki.root])


@pytest.mark.asyncio
async def test_select_certificate(profile, pki: Pki, multikey):
    key = wallet_public_key(multikey)
    short = pki.leaf(key, not_after=NOW + timedelta(days=10))
    medium = pki.leaf(key, not_after=NOW + timedelta(days=20))
    long_ = pki.leaf(key, not_after=NOW + timedelta(days=30))
    future = pki.leaf(key, not_before=NOW + timedelta(days=1))
    async with profile.session() as session:
        for cert, purpose in [
            (short, "sd_jwt_vc_issuer"),
            (long_, "sd_jwt_vc_issuer"),
            (medium, "sd_jwt_vc_issuer"),
            (future, "sd_jwt_vc_issuer"),
            (medium, "mdoc_ds"),
        ]:
            await X509CertificateRecord(
                multikey=multikey, purpose=purpose, x5c=to_x5c([cert]), **describe(cert)
            ).save(session)

        chosen = await select_certificate(
            session, multikey, "sd_jwt_vc_issuer", NOW + timedelta(days=15)
        )
        assert chosen.not_after == medium.not_valid_after_utc.isoformat()

        with pytest.raises(X509Error, match="No sd_jwt_vc_issuer certificate"):
            await select_certificate(
                session, multikey, "sd_jwt_vc_issuer", NOW + timedelta(days=60)
            )


def test_verify_chain_to_root(pki: Pki, multikey):
    leaf = pki.leaf(wallet_public_key(multikey))
    assert verify_chain([leaf, pki.intermediate], [pki.root], NOW) == pki.root
    assert verify_chain([leaf, pki.intermediate, pki.root], [pki.root], NOW) == pki.root


def test_verify_chain_to_intermediate_anchor(pki: Pki, multikey):
    leaf = pki.leaf(wallet_public_key(multikey))
    assert verify_chain([leaf], [pki.intermediate], NOW) == pki.intermediate


def test_verify_chain_failures(pki: Pki, multikey):
    key = wallet_public_key(multikey)
    leaf = pki.leaf(key)
    with pytest.raises(X509Error, match="does not lead to a trust anchor"):
        verify_chain([leaf, pki.intermediate], [Pki("Other").root], NOW)
    with pytest.raises(X509Error, match="not valid at"):
        verify_chain([leaf, pki.intermediate], [pki.root], NOW + timedelta(days=60))
    with pytest.raises(X509Error, match="not issued by"):
        verify_chain([leaf, Pki("Other").intermediate], [pki.root], NOW)

    # A non-CA certificate cannot issue.
    not_ca_key = ec.generate_private_key(ec.SECP256R1())
    not_ca = pki.leaf(not_ca_key.public_key())
    issued = (
        x509.CertificateBuilder()
        .subject_name(leaf.subject)
        .issuer_name(not_ca.subject)
        .public_key(key)
        .serial_number(1)
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=1))
        .sign(not_ca_key, hashes.SHA256())
    )
    with pytest.raises(X509Error, match="not a CA"):
        verify_chain([issued, not_ca, pki.intermediate], [pki.root], NOW)


@pytest.mark.asyncio
async def test_build_csr_signed_by_wallet_key(profile, multikey):
    async with profile.session() as session:
        wallet = session.inject(BaseWallet)
        verkey = multikey_to_verkey(multikey)
        key_type = (await wallet.get_signing_key(verkey)).key_type
        pem = await build_csr(
            wallet,
            verkey,
            key_type,
            {"common_name": "Issuer", "country": "CA"},
            dns_names=["issuer.example.com"],
        )

    csr = x509.load_pem_x509_csr(pem.encode())
    assert csr.is_signature_valid
    assert csr.public_key() == wallet_public_key(multikey)
    assert csr.subject.rfc4514_string() == "C=CA,CN=Issuer"


@pytest.mark.asyncio
async def test_build_self_signed(profile, multikey):
    async with profile.session() as session:
        wallet = session.inject(BaseWallet)
        verkey = multikey_to_verkey(multikey)
        key_type = (await wallet.get_signing_key(verkey)).key_type
        cert = await build_self_signed(
            wallet, verkey, key_type, {"common_name": "Demo"}, 7
        )

    assert is_self_signed(cert)
    assert public_key_multikey(cert) == multikey
    assert describe(cert)["subject"] == "CN=Demo"


@pytest.mark.asyncio
async def test_signing_rejects_non_p256_and_bad_subject(profile, multikey):
    async with profile.session() as session:
        wallet = session.inject(BaseWallet)
        verkey = multikey_to_verkey(multikey)
        with pytest.raises(X509Error, match="Only p256"):
            await build_csr(wallet, verkey, ED25519, {"common_name": "x"})
        key_type = (await wallet.get_signing_key(verkey)).key_type
        with pytest.raises(X509Error, match="Unknown subject fields"):
            await build_csr(wallet, verkey, key_type, {"email": "x"})
        with pytest.raises(X509Error, match="at least one field"):
            await build_csr(wallet, verkey, key_type, {})
