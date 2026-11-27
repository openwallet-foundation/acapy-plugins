"""End-to-end test: OID4VCI pre-authorized code flow with Keycloak as the AS.

A scripted wallet drives the whole flow against the compose stack:

1. issuer controller creates a credential configuration and an offer with a tx_code;
2. wallet discovers the authorization server from the issuer metadata;
3. negative checks: token request without wallet attestation, wrong tx_code,
   authorization_details for a credential configuration the offer doesn't
   include (rejected without consuming the code);
4. token request to Keycloak with wallet attestation (ABCA) + DPoP +
   authorization_details; the response returns them with credential_identifiers;
5. nonce + credential request to the issuer (by credential_identifier) with the
   DPoP-bound token;
6. refresh: a refresh from a different wallet instance is rejected (the
   refresh token is bound to the attested instance key); a refresh while
   no new credential is offered yields a token but no credential; after the
   controller triggers a credential refresh, the rotated refresh token gets
   a new access token and the new credential; reusing a rotated refresh token
   is rejected;
7. negative checks: a refresh token presented as an access token; the
   DPoP-bound token used as a Bearer token; the redeem endpoint is absent
   from the public port and rejects unauthenticated calls on the admin port.

With E2E_DPOP=false the realm, the wallet client and the plugin are switched
to DPoP off first, and the same flow runs with Bearer tokens: the refresh
token is then bound to the attested instance key only.

TEST ONLY: the attester key in attester-demo-key.json is public.
"""

import base64
import hashlib
import json
import os
import sys
import time
import uuid
from urllib.parse import quote

import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

ADMIN_URL = os.environ.get("ADMIN_URL", "http://localhost:3001")
CLIENT_ID = os.environ.get("CLIENT_ID", "demo-wallet")
KEYCLOAK_URL = os.environ.get("KEYCLOAK_URL", "http://localhost:8180")
REALM = "oid4vci"
DPOP = os.environ.get("E2E_DPOP", "true").lower() != "false"
TOKEN_TYPE = "DPoP" if DPOP else "Bearer"
ATTESTER_ISS = "https://attester.demo.example"
TX_CODE = "493536"
PRE_AUTH_GRANT = "urn:ietf:params:oauth:grant-type:pre-authorized_code"


# --- JOSE helpers -------------------------------------------------------------


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64int(value: int) -> str:
    return b64(value.to_bytes(32, "big"))


def unb64int(value: str) -> int:
    return int.from_bytes(
        base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)), "big"
    )


def public_jwk(key: ec.EllipticCurvePrivateKey) -> dict:
    nums = key.public_key().public_numbers()
    return {"kty": "EC", "crv": "P-256", "x": b64int(nums.x), "y": b64int(nums.y)}


def load_attester_key() -> tuple[ec.EllipticCurvePrivateKey, str]:
    with open("attester-demo-key.json") as f:
        jwk = json.load(f)["jwk"]
    public = ec.EllipticCurvePublicNumbers(
        unb64int(jwk["x"]), unb64int(jwk["y"]), ec.SECP256R1()
    )
    key = ec.EllipticCurvePrivateNumbers(unb64int(jwk["d"]), public).private_key()
    return key, jwk["kid"]


def sign(key: ec.EllipticCurvePrivateKey, header: dict, payload: dict) -> str:
    signing_input = (
        b64(json.dumps({"alg": "ES256", **header}).encode())
        + "."
        + b64(json.dumps(payload).encode())
    )
    r, s = decode_dss_signature(
        key.sign(signing_input.encode(), ec.ECDSA(hashes.SHA256()))
    )
    return signing_input + "." + b64(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def dpop_proof(key, htm: str, htu: str, access_token: str | None = None) -> str:
    payload = {"jti": str(uuid.uuid4()), "htm": htm, "htu": htu, "iat": int(time.time())}
    if access_token:
        payload["ath"] = b64(hashlib.sha256(access_token.encode()).digest())
    return sign(key, {"typ": "dpop+jwt", "jwk": public_jwk(key)}, payload)


class Wallet:
    """Wallet instance with an attestation from the (demo) wallet provider."""

    def __init__(self):
        self.instance_key = ec.generate_private_key(ec.SECP256R1())
        self.dpop_key = ec.generate_private_key(ec.SECP256R1())
        self.holder_key = ec.generate_private_key(ec.SECP256R1())
        attester_key, kid = load_attester_key()
        now = int(time.time())
        # Issued by the wallet provider's attester, binding the instance key.
        # Keycloak 26.8.0 takes the PoP verification algorithm from cnf.jwk's
        # "alg" and has no fallback for EC keys, so it must be present.
        self.attestation = sign(
            attester_key,
            {"typ": "oauth-client-attestation+jwt", "kid": kid},
            {
                "iss": ATTESTER_ISS,
                "sub": CLIENT_ID,
                "iat": now,
                "exp": now + 3600,
                "cnf": {"jwk": {**public_jwk(self.instance_key), "alg": "ES256"}},
            },
        )

    def attestation_headers(self, as_issuer: str) -> dict:
        pop = sign(
            self.instance_key,
            {"typ": "oauth-client-attestation-pop+jwt"},
            {
                "iss": CLIENT_ID,
                "aud": as_issuer,
                "jti": str(uuid.uuid4()),
                "iat": int(time.time()),
            },
        )
        return {
            "OAuth-Client-Attestation": self.attestation,
            "OAuth-Client-Attestation-PoP": pop,
        }


# --- Flow ------------------------------------------------------------------------


def step(title: str):
    print(f"\n=== {title}")


def expect(
    resp: requests.Response, status: int | tuple, label: str, error: str | None = None
) -> dict:
    try:
        body = resp.json()
    except ValueError:
        body = {"raw": resp.text}
    ok = resp.status_code in (status if isinstance(status, tuple) else (status,))
    if error is not None:
        ok = ok and isinstance(body, dict) and body.get("error") == error
    print(
        f"[{'ok' if ok else 'FAIL'}] {label}: HTTP {resp.status_code} {json.dumps(body)[:300]}"
    )
    if not ok:
        sys.exit(1)
    return body


def admin(method: str, path: str, **kwargs) -> dict:
    resp = requests.request(method, f"{ADMIN_URL}{path}", timeout=30, **kwargs)
    resp.raise_for_status()
    return resp.json()


def disable_dpop():
    """Switch the realm, the wallet client and the plugin to DPoP off."""
    step("Setup: DPoP off (realm, wallet client, plugin)")
    token = requests.post(
        f"{KEYCLOAK_URL}/realms/master/protocol/openid-connect/token",
        data={
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": "admin",
            "password": "admin",
        },
        timeout=10,
    )
    token.raise_for_status()
    headers = {"Authorization": f"Bearer {token.json()['access_token']}"}
    realm_url = f"{KEYCLOAK_URL}/admin/realms/{REALM}"

    realm = requests.get(realm_url, headers=headers, timeout=10).json()
    realm["attributes"]["oid4vci.require.dpop"] = "false"
    requests.put(realm_url, json=realm, headers=headers, timeout=10).raise_for_status()

    client = requests.get(
        f"{realm_url}/clients",
        params={"clientId": CLIENT_ID},
        headers=headers,
        timeout=10,
    ).json()[0]
    client["attributes"]["dpop.bound.access.tokens"] = "false"
    requests.put(
        f"{realm_url}/clients/{client['id']}", json=client, headers=headers, timeout=10
    ).raise_for_status()
    print("realm oid4vci.require.dpop=false, client dpop.bound.access.tokens=false")


def dpop_headers(key, htm: str, htu: str, access_token: str | None = None) -> dict:
    return {"DPoP": dpop_proof(key, htm, htu, access_token)} if DPOP else {}


def create_offer() -> tuple[dict, str, dict]:
    step("Issuer controller: credential configuration + offer (tx_code required)")
    did = admin("POST", "/did/jwk/create", json={"key_type": "p256"})["did"]
    # The plugin-level OID4VCI_AUTH_SERVER requires DPoP; with DPoP off the
    # base wallet's IssuerConfiguration overrides it.
    issuer_config = (
        {}
        if DPOP
        else {
            "authorization_servers": [
                {
                    "type": "keycloak",
                    "public_url": f"http://keycloak:8080/realms/{REALM}",
                    "require_dpop": False,
                }
            ]
        }
    )
    admin("PUT", "/oid4vci/issuer/configuration", json=issuer_config)
    config_id = f"DemoCredential-{uuid.uuid4().hex[:8]}"
    supported = admin(
        "POST",
        "/oid4vci/credential-supported/create/jwt",
        json={
            "cryptographic_binding_methods_supported": ["jwk"],
            "credential_signing_alg_values_supported": ["ES256"],
            "format": "jwt_vc_json",
            "id": config_id,
            "credential_definition": {
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                "type": ["VerifiableCredential", "DemoCredential"],
            },
        },
    )
    exchange_body = {
        "supported_cred_id": supported["supported_cred_id"],
        "credential_subject": {"name": "Tom"},
        "verification_method": f"{did}#0",
    }
    exchange = admin(
        "POST", "/oid4vci/exchange/create", json={**exchange_body, "pin": TX_CODE}
    )
    offer = admin(
        "GET",
        "/oid4vci/credential-offer",
        params={"exchange_id": exchange["exchange_id"]},
    )["offer"]
    print(json.dumps(offer, indent=2))
    return offer, config_id, exchange_body


def jwt_claims(token: str) -> dict:
    return json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "==").decode())


def main():
    print(f"DPoP: {'on' if DPOP else 'off'}")
    if not DPOP:
        disable_dpop()
    offer, config_id, exchange_body = create_offer()
    code = offer["grants"][PRE_AUTH_GRANT]["pre-authorized_code"]
    issuer = offer["credential_issuer"]

    step("Wallet: discovery")
    meta = expect(
        requests.get(f"{issuer}/.well-known/openid-credential-issuer", timeout=10),
        200,
        "issuer metadata",
    )
    auth_server = meta["authorization_servers"][0]
    as_meta = expect(
        requests.get(f"{auth_server}/.well-known/openid-configuration", timeout=10),
        200,
        "authorization server metadata",
    )
    token_endpoint = as_meta["token_endpoint"]
    print(f"authorization server: {auth_server}\ntoken endpoint: {token_endpoint}")

    wallet = Wallet()

    def authorization_details(configuration_id: str) -> str:
        # OID4VCI 1.0 §5.1.1: locations = the credential issuer when the
        # authorization server is separate.
        return json.dumps(
            [
                {
                    "type": "openid_credential",
                    "credential_configuration_id": configuration_id,
                    "locations": [issuer],
                }
            ]
        )

    form = {
        "grant_type": PRE_AUTH_GRANT,
        "pre-authorized_code": code,
        "tx_code": TX_CODE,
        "client_id": CLIENT_ID,
        "authorization_details": authorization_details(config_id),
    }

    step("Negative: token request without wallet attestation")
    expect(
        requests.post(
            token_endpoint,
            data=form,
            headers=dpop_headers(wallet.dpop_key, "POST", token_endpoint),
            timeout=10,
        ),
        (400, 401),
        "rejected (client attestation required)",
    )

    step("Negative: wrong tx_code (counts towards the lockout)")
    expect(
        requests.post(
            token_endpoint,
            data={**form, "tx_code": "000000"},
            headers={
                **wallet.attestation_headers(as_meta["issuer"]),
                **dpop_headers(wallet.dpop_key, "POST", token_endpoint),
            },
            timeout=10,
        ),
        400,
        "rejected (invalid_grant)",
        error="invalid_grant",
    )

    step("Negative: authorization_details for a configuration not in the offer")
    expect(
        requests.post(
            token_endpoint,
            data={**form, "authorization_details": authorization_details("Other")},
            headers={
                **wallet.attestation_headers(as_meta["issuer"]),
                **dpop_headers(wallet.dpop_key, "POST", token_endpoint),
            },
            timeout=10,
        ),
        400,
        "rejected (code not consumed)",
        error="invalid_authorization_details",
    )

    step(
        f"Token request: wallet attestation{' + DPoP' if DPOP else ''}"
        " + tx_code + authorization_details"
    )
    token = expect(
        requests.post(
            token_endpoint,
            data=form,
            headers={
                **wallet.attestation_headers(as_meta["issuer"]),
                **dpop_headers(wallet.dpop_key, "POST", token_endpoint),
            },
            timeout=10,
        ),
        200,
        "access token",
    )
    access_token = token["access_token"]
    assert token["token_type"] == TOKEN_TYPE, token["token_type"]
    # OID4VCI §6.2: authorization_details with credential_identifiers
    granted = token.get("authorization_details")
    assert granted and granted[0]["credential_identifiers"] == [config_id], granted
    credential_identifier = granted[0]["credential_identifiers"][0]
    claims = jwt_claims(access_token)
    assert claims["authorization_details"] == granted, claims
    print("access token claims:", json.dumps(claims, indent=2))
    refresh_token = token.get("refresh_token")
    assert refresh_token, "no refresh token issued"
    print(f"refresh token issued, expires in {token.get('refresh_expires_in')} s")

    cred_endpoint = meta["credential_endpoint"]

    def request_credential(at: str):
        nonce = expect(requests.post(meta["nonce_endpoint"], timeout=10), 200, "nonce")
        proof = sign(
            wallet.holder_key,
            {"typ": "openid4vci-proof+jwt", "jwk": public_jwk(wallet.holder_key)},
            {"aud": issuer, "iat": int(time.time()), "nonce": nonce["c_nonce"]},
        )
        return requests.post(
            cred_endpoint,
            json={
                "credential_identifier": credential_identifier,
                "proofs": {"jwt": [proof]},
            },
            headers={
                "Authorization": f"{TOKEN_TYPE} {at}",
                **dpop_headers(wallet.dpop_key, "POST", cred_endpoint, at),
            },
            timeout=30,
        )

    def refresh(rt: str, instance: "Wallet" = wallet) -> requests.Response:
        return requests.post(
            token_endpoint,
            data={
                "grant_type": "refresh_token",
                "refresh_token": rt,
                "client_id": CLIENT_ID,
            },
            headers={
                # Attestation-based client: the attestation is presented again, and
                # Keycloak binds the refresh token to the attested instance key.
                # (For public clients it is bound to the DPoP key instead.)
                **instance.attestation_headers(as_meta["issuer"]),
                **dpop_headers(instance.dpop_key, "POST", token_endpoint),
            },
            timeout=10,
        )

    step(f"Nonce + credential request ({TOKEN_TYPE} token)")
    credential = expect(request_credential(access_token), 200, "credential")
    print("credential:", credential["credentials"][0]["credential"][:120], "...")

    step("Negative: refresh from a different wallet instance")
    expect(
        refresh(refresh_token, Wallet()),
        400,
        "rejected (refresh token bound to the attested instance key)",
        error="invalid_grant",
    )

    step("Refresh while no new credential is offered")
    refreshed = expect(refresh(refresh_token), 200, "refreshed token")
    assert refreshed["token_type"] == TOKEN_TYPE, refreshed["token_type"]
    refreshed_claims = jwt_claims(refreshed["access_token"])
    assert refreshed_claims["refresh_id"] == claims["refresh_id"], refreshed_claims
    assert refreshed_claims["authorization_details"] == granted, refreshed_claims
    assert refreshed["refresh_token"] != refresh_token, "refresh token not rotated"
    expect(
        request_credential(refreshed["access_token"]),
        400,
        "no credential: the issuer has not offered a refreshed one",
    )

    step("Issuer controller: credential refresh")
    admin(
        "PATCH",
        f"/oid4vci/credential-refresh/{claims['refresh_id']}",
        json={**exchange_body, "credential_subject": {"name": "Tom", "refreshed": True}},
    )

    step("Refresh with the rotated refresh token + new credential")
    rotated = expect(refresh(refreshed["refresh_token"]), 200, "refreshed token")
    credential = expect(
        request_credential(rotated["access_token"]), 200, "new credential"
    )
    print("credential:", credential["credentials"][0]["credential"][:120], "...")

    step("Negative: reuse of a rotated refresh token")
    expect(
        refresh(refresh_token),
        400,
        "rejected (rotation)",
        error="invalid_grant",
    )

    step("Negative: refresh token presented as an access token")
    current_refresh_token = rotated["refresh_token"]
    expect(
        requests.post(
            cred_endpoint,
            json={"credential_configuration_id": config_id},
            headers={
                "Authorization": f"{TOKEN_TYPE} {current_refresh_token}",
                **dpop_headers(
                    wallet.dpop_key, "POST", cred_endpoint, current_refresh_token
                ),
            },
            timeout=10,
        ),
        401,
        "rejected",
    )

    if DPOP:
        step("Negative: DPoP-bound token presented as Bearer")
        expect(
            requests.post(
                cred_endpoint,
                json={"credential_configuration_id": config_id},
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=10,
            ),
            401,
            "rejected",
        )

    step("Negative: redeem endpoint (trusted back channel)")
    expect(
        requests.post(f"{issuer}/oid4vci/pre-auth/redeem", data={}, timeout=10),
        404,
        "not served on the public OID4VCI port",
    )
    expect(
        requests.post(
            f"{ADMIN_URL}/oid4vci/pre-auth/redeem",
            data={"pre_authorized_code": code, "client_id": "anyone"},
            timeout=10,
        ),
        401,
        "admin port: rejected without Keycloak's client authentication",
        error="invalid_client",
    )
    print("\nDone.")
    print(
        f"Offer link: openid-credential-offer://?credential_offer={quote(json.dumps(offer))}"
    )


if __name__ == "__main__":
    main()
