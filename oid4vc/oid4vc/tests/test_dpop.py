import time

import pytest

from oid4vc.dpop import DPoPError, normalize_htu, verify_dpop_proof
from oid4vc.jose_util import jwk_thumbprint

from .jose_helpers import dpop_proof, ec_key, public_jwk

HTU = "https://issuer.example/credential"


def test_valid_proof_returns_thumbprint():
    key = ec_key()
    jkt = verify_dpop_proof(dpop_proof(key), htm="POST", htu=HTU)
    assert jkt == jwk_thumbprint(public_jwk(key))


def test_valid_proof_with_access_token_and_binding():
    key = ec_key()
    jkt = jwk_thumbprint(public_jwk(key))
    proof = dpop_proof(key, access_token="tok")
    assert (
        verify_dpop_proof(
            proof, htm="POST", htu=HTU, access_token="tok", expected_jkt=jkt
        )
        == jkt
    )


def test_htu_normalization():
    assert normalize_htu("HTTPS://Issuer.Example:443/credential/?a=1#f") == HTU
    key = ec_key()
    verify_dpop_proof(
        dpop_proof(key, htu="https://issuer.example:443/credential?x=1"),
        htm="post",
        htu=HTU,
    )


@pytest.mark.parametrize(
    "kwargs, verify_kwargs, message",
    [
        ({"htu": "https://other.example/credential"}, {}, "htu"),
        ({"htu": "https://issuer.example:abc/credential"}, {}, "htu"),
        ({"htu": "https://[::1/credential"}, {}, "htu"),
        ({"htm": "GET"}, {}, "htm"),
        ({"iat": int(time.time()) - 3600}, {}, "iat"),
        ({"iat": int(time.time()) + 3600}, {}, "iat"),
        ({"typ": "JWT"}, {}, "typ"),
        ({"access_token": "other"}, {"access_token": "tok"}, "ath"),
        ({}, {"access_token": "tok"}, "ath"),
        ({}, {"expected_jkt": "not-the-key"}, "binding"),
    ],
)
def test_invalid_proofs(kwargs, verify_kwargs, message):
    key = ec_key()
    with pytest.raises(DPoPError) as exc:
        verify_dpop_proof(dpop_proof(key, **kwargs), htm="POST", htu=HTU, **verify_kwargs)
    assert message in exc.value.description


def test_any_of_several_htus_is_accepted():
    key = ec_key()
    published = "https://issuer.example.com/custom-credential"
    proof = dpop_proof(key, htu=published)
    verify_dpop_proof(proof, htm="POST", htu=[HTU, published])
    with pytest.raises(DPoPError, match="htu"):
        verify_dpop_proof(dpop_proof(key, htu=published), htm="POST", htu=[HTU])


def test_missing_proof():
    with pytest.raises(DPoPError):
        verify_dpop_proof(None, htm="POST", htu=HTU)


def test_signature_from_other_key_rejected():
    key, other = ec_key(), ec_key()
    with pytest.raises(DPoPError) as exc:
        verify_dpop_proof(dpop_proof(key, jwk=public_jwk(other)), htm="POST", htu=HTU)
    assert "signature" in exc.value.description


def test_private_key_in_header_rejected():
    key = ec_key()
    jwk = {**public_jwk(key), "d": "AAAA"}
    with pytest.raises(DPoPError) as exc:
        verify_dpop_proof(dpop_proof(key, jwk=jwk), htm="POST", htu=HTU)
    assert "private" in exc.value.description


def test_replayed_jti_rejected():
    key = ec_key()
    proof = dpop_proof(key)
    verify_dpop_proof(proof, htm="POST", htu=HTU)
    with pytest.raises(DPoPError) as exc:
        verify_dpop_proof(proof, htm="POST", htu=HTU)
    assert "jti" in exc.value.description


def test_rejected_proof_does_not_burn_jti():
    key = ec_key()
    proof = dpop_proof(key, jti="fixed-jti")
    with pytest.raises(DPoPError):
        verify_dpop_proof(proof, htm="GET", htu=HTU)
    verify_dpop_proof(proof, htm="POST", htu=HTU)
