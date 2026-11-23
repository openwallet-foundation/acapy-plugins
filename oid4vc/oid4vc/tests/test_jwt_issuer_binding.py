"""Tests for issuer and holder key binding in JWT verification."""

import base64
import datetime
import hashlib
import json

import pytest
from acapy_agent.core.profile import Profile
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

from jwt_vc_json import JwtVcJsonCredProcessor
from oid4vc.jose_util import b64url_encode
from oid4vc.jwt import jwt_verify
from sd_jwt_vc.cred_processor import sd_jwt_verify

from .jose_helpers import ec_key, ed_key, public_jwk, sign

AUD = "https://verifier.example.com"
NONCE = "n-0S6_WzA2Mj"


def did_jwk(key) -> str:
    return "did:jwk:" + b64url_encode(json.dumps(public_jwk(key)).encode())


def self_signed_x5c(key) -> list:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "issuer")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return [base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()]


def claims(iss: str, **extra) -> dict:
    return {"iss": iss, "iat": 1700000000, "exp": 1900000000, **extra}


@pytest.fixture
def issuer():
    return ec_key()


@pytest.fixture
def attacker():
    return ec_key()


class TestIssuerBoundVerify:
    async def test_kid_of_iss(self, profile: Profile, issuer):
        iss = did_jwk(issuer)
        jwt = sign({"kid": f"{iss}#0"}, claims(iss), issuer, "ES256")

        result = await jwt_verify(profile, jwt, issuer_bound=True)
        assert result.verified

    async def test_relative_kid(self, profile: Profile, issuer):
        iss = did_jwk(issuer)
        jwt = sign({"kid": "#0"}, claims(iss), issuer, "ES256")

        result = await jwt_verify(profile, jwt, issuer_bound=True)
        assert result.verified

    async def test_jwk_header_of_iss(self, profile: Profile, issuer):
        iss = did_jwk(issuer)
        jwt = sign({"jwk": public_jwk(issuer)}, claims(iss), issuer, "ES256")

        result = await jwt_verify(profile, jwt, issuer_bound=True)
        assert result.verified

    async def test_x5c_with_iss_key(self, profile: Profile, issuer):
        iss = did_jwk(issuer)
        jwt = sign({"x5c": self_signed_x5c(issuer)}, claims(iss), issuer, "ES256")

        result = await jwt_verify(profile, jwt, issuer_bound=True)
        assert result.verified

    async def test_x_jwk_header_not_iss_key(self, profile: Profile, issuer, attacker):
        jwt = sign(
            {"jwk": public_jwk(attacker)}, claims(did_jwk(issuer)), attacker, "ES256"
        )

        with pytest.raises(Exception, match="not a key of the 'iss' DID"):
            await jwt_verify(profile, jwt, issuer_bound=True)

    async def test_x_kid_of_other_did(self, profile: Profile, issuer, attacker):
        jwt = sign(
            {"kid": f"{did_jwk(attacker)}#0"},
            claims(did_jwk(issuer)),
            attacker,
            "ES256",
        )

        with pytest.raises(Exception, match="not a key of the 'iss' DID"):
            await jwt_verify(profile, jwt, issuer_bound=True)

    async def test_x_x5c_not_iss_key(self, profile: Profile, issuer, attacker):
        jwt = sign(
            {"x5c": self_signed_x5c(attacker)},
            claims(did_jwk(issuer)),
            attacker,
            "ES256",
        )

        with pytest.raises(Exception, match="not a key of the 'iss' DID"):
            await jwt_verify(profile, jwt, issuer_bound=True)

    async def test_x_iss_not_did(self, profile: Profile, issuer):
        jwt = sign(
            {"jwk": public_jwk(issuer)},
            claims("https://issuer.example.com"),
            issuer,
            "ES256",
        )

        with pytest.raises(Exception, match="'iss' must be a DID"):
            await jwt_verify(profile, jwt, issuer_bound=True)

    async def test_x_iss_missing(self, profile: Profile, issuer):
        jwt = sign({"kid": f"{did_jwk(issuer)}#0"}, {"iat": 1}, issuer, "ES256")

        with pytest.raises(Exception, match="'iss' must be a DID"):
            await jwt_verify(profile, jwt, issuer_bound=True)


class TestCnfKidVerify:
    async def test_cnf_kid_without_header_kid(self, profile: Profile, issuer):
        kid = f"{did_jwk(issuer)}#0"
        jwt = sign({"typ": "kb+jwt"}, {"aud": AUD}, issuer, "ES256")

        result = await jwt_verify(profile, jwt, cnf={"kid": kid})
        assert result.verified

    async def test_x_cnf_kid_header_kid_mismatch(
        self, profile: Profile, issuer, attacker
    ):
        jwt = sign(
            {"typ": "kb+jwt", "kid": f"{did_jwk(attacker)}#0"},
            {"aud": AUD},
            attacker,
            "ES256",
        )

        with pytest.raises(Exception, match="does not match cnf"):
            await jwt_verify(profile, jwt, cnf={"kid": f"{did_jwk(issuer)}#0"})

    async def test_x_cnf_kid_signed_by_other_key(
        self, profile: Profile, issuer, attacker
    ):
        jwt = sign({"typ": "kb+jwt"}, {"aud": AUD}, attacker, "ES256")

        result = await jwt_verify(profile, jwt, cnf={"kid": f"{did_jwk(issuer)}#0"})
        assert not result.verified


def corrupt_signature(jwt: str) -> str:
    header, payload, sig = jwt.split(".")
    flipped = "A" if sig[0] != "A" else "B"
    return f"{header}.{payload}.{flipped}{sig[1:]}"


class TestSdJwtVerify:
    def issue(self, issuer, holder, iss=None, header=None) -> str:
        iss = iss or did_jwk(issuer)
        payload = claims(
            iss,
            vct="IdentityCredential",
            _sd_alg="sha-256",
            _sd=[],
            given_name="Alice",
            cnf={"jwk": public_jwk(holder)},
        )
        header = header or {"kid": f"{did_jwk(issuer)}#0"}
        return sign({"typ": "dc+sd-jwt", **header}, payload, issuer, "ES256") + "~"

    def key_binding(self, sd_jwt: str, holder, aud=AUD, nonce=NONCE) -> str:
        sd_hash = b64url_encode(hashlib.sha256(sd_jwt.encode("ascii")).digest())
        return sign(
            {"typ": "kb+jwt"},
            {"aud": aud, "nonce": nonce, "iat": 1700000000, "sd_hash": sd_hash},
            holder,
            "ES256",
        )

    async def test_presentation(self, profile: Profile, issuer):
        holder = ec_key()
        sd_jwt = self.issue(issuer, holder)
        presentation = sd_jwt + self.key_binding(sd_jwt, holder)

        result = await sd_jwt_verify(profile, presentation, AUD, NONCE)
        assert result.verified
        assert result.payload["given_name"] == "Alice"

    async def test_credential(self, profile: Profile, issuer):
        result = await sd_jwt_verify(profile, self.issue(issuer, ec_key()))
        assert result.verified

    async def test_x_issuer_jwk_header_not_iss_key(
        self, profile: Profile, issuer, attacker
    ):
        sd_jwt = self.issue(
            attacker,
            ec_key(),
            iss=did_jwk(issuer),
            header={"jwk": public_jwk(attacker)},
        )

        result = await sd_jwt_verify(profile, sd_jwt)
        assert not result.verified

    async def test_x_issuer_kid_of_other_did(self, profile: Profile, issuer, attacker):
        sd_jwt = self.issue(attacker, ec_key(), iss=did_jwk(issuer))

        result = await sd_jwt_verify(profile, sd_jwt)
        assert not result.verified

    async def test_x_key_binding_bad_signature(self, profile: Profile, issuer):
        holder = ec_key()
        sd_jwt = self.issue(issuer, holder)
        presentation = sd_jwt + corrupt_signature(self.key_binding(sd_jwt, holder))

        result = await sd_jwt_verify(profile, presentation, AUD, NONCE)
        assert not result.verified

    async def test_x_key_binding_other_key(self, profile: Profile, issuer, attacker):
        sd_jwt = self.issue(issuer, ec_key())
        presentation = sd_jwt + self.key_binding(sd_jwt, attacker)

        result = await sd_jwt_verify(profile, presentation, AUD, NONCE)
        assert not result.verified


class TestJwtVcJsonVerify:
    def credential(self, signer, iss: str, header: dict) -> str:
        payload = claims(
            iss,
            vc={
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                "type": ["VerifiableCredential"],
                "issuer": iss,
                "credentialSubject": {"name": "Alice"},
            },
        )
        return sign(header, payload, signer, "EdDSA")

    async def test_credential(self, profile: Profile):
        issuer = ed_key()
        iss = did_jwk(issuer)
        jwt = self.credential(issuer, iss, {"kid": f"{iss}#0"})

        result = await JwtVcJsonCredProcessor().verify_credential(profile, jwt)
        assert result.verified

    async def test_x_jwk_header_not_iss_key(self, profile: Profile):
        issuer, attacker = ed_key(), ed_key()
        jwt = self.credential(attacker, did_jwk(issuer), {"jwk": public_jwk(attacker)})

        result = await JwtVcJsonCredProcessor().verify_credential(profile, jwt)
        assert not result.verified
