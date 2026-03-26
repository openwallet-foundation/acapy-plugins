"""Step-by-step tests for jwt_vc_json credential issuance via Credo.

Each test covers exactly one step of the issuance flow so we can pinpoint
exactly which step fails — rather than reading a 250-line test that fails
at line 123 with "Failed to extract credential JWT".

Test order:
  1. Infrastructure health checks
  2. ACA-Py credential config creation
  3. ACA-Py credential offer creation
  4. Credo offer resolution (via /debug/resolve-offer)
  5. Credo credential acceptance (binding resolver inspection)
  6. Credential value presence (non-null)
  7. Credential value is a valid JWT string
  8. Credential has expected VC payload shape

Run with:
    pytest tests/debug/test_jwt_vc_steps.py -v

These tests intentionally share no state — every test creates its own
fresh credential config + exchange so failures don't cascade.
"""

import uuid

import jwt
import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

JWT_VC_FORMAT = "jwt_vc_json"


async def _make_config(acapy_issuer_admin, suffix: str) -> dict:
    """Create a minimal jwt_vc_json credential config in ACA-Py.

    NOTE: type and @context MUST be inside format_data (not at the top level).
    When placed at the top level, ACA-Py moves them to vc_additional_data, leaving
    credential_definition empty in the issuer metadata.  An empty credential_definition
    causes @openid4vc/openid4vci 0.4.x to exclude the config from
    knownCredentialConfigurations, resulting in offeredCredentialConfigurations={} and
    zero credentials returned by requestCredentials (with no error).
    """
    config = {
        "id": f"DebugJwtVc_{suffix}",
        "format": JWT_VC_FORMAT,
        "format_data": {
            "type": ["VerifiableCredential", "DebugTestCredential"],
            "@context": ["https://www.w3.org/2018/credentials/v1"],
        },
        "proof_types_supported": {
            "jwt": {"proof_signing_alg_values_supported": ["EdDSA", "ES256"]}
        },
        "display": [{"name": "Debug Test Credential", "locale": "en-US"}],
    }
    return await acapy_issuer_admin.post(
        "/oid4vci/credential-supported/create", json=config
    )


async def _make_offer(acapy_issuer_admin, supported_cred_id: str) -> dict:
    """Create a credential exchange and return the offer payload."""
    did_resp = await acapy_issuer_admin.post(
        "/wallet/did/create",
        json={"method": "key", "options": {"key_type": "ed25519"}},
    )
    issuer_did = did_resp["result"]["did"]

    exchange = await acapy_issuer_admin.post(
        "/oid4vci/exchange/create",
        json={
            "supported_cred_id": supported_cred_id,
            "credential_subject": {
                "given_name": "Debug",
                "family_name": "Tester",
            },
            "did": issuer_did,
        },
    )
    offer = await acapy_issuer_admin.get(
        "/oid4vci/credential-offer",
        params={"exchange_id": exchange["exchange_id"]},
    )
    return {"offer": offer["credential_offer"], "exchange_id": exchange["exchange_id"]}


# ---------------------------------------------------------------------------
# Step 1 — Infrastructure health
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_step1_credo_agent_is_healthy(credo_client):
    """Step 1: Credo agent HTTP service is reachable and reports healthy."""
    resp = await credo_client.get("/health")
    assert resp.status_code == 200, (
        f"Credo health returned {resp.status_code}: {resp.text}"
    )
    data = resp.json()
    assert data.get("status") == "healthy", f"Unexpected health body: {data}"


@pytest.mark.asyncio
async def test_step1_acapy_issuer_is_ready(acapy_issuer_admin):
    """Step 1b: ACA-Py issuer admin API is reachable and marked ready."""
    status = await acapy_issuer_admin.get("/status/ready")
    assert status.get("ready") is True, f"ACA-Py issuer not ready: {status}"


# ---------------------------------------------------------------------------
# Step 2 — ACA-Py credential config
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_step2_create_jwt_vc_json_credential_config(acapy_issuer_admin):
    """Step 2: ACA-Py accepts a jwt_vc_json credential-supported creation request."""
    suffix = str(uuid.uuid4())[:8]
    resp = await _make_config(acapy_issuer_admin, suffix)
    assert "supported_cred_id" in resp, (
        f"Expected 'supported_cred_id' in response, got: {resp}"
    )
    assert resp["supported_cred_id"], "supported_cred_id must be non-empty"


# ---------------------------------------------------------------------------
# Step 3 — ACA-Py credential offer
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_step3_create_jwt_vc_json_offer(acapy_issuer_admin):
    """Step 3: ACA-Py creates a valid credential offer for jwt_vc_json."""
    suffix = str(uuid.uuid4())[:8]
    config = await _make_config(acapy_issuer_admin, suffix)
    result = await _make_offer(acapy_issuer_admin, config["supported_cred_id"])
    offer = result["offer"]

    # Offer must be a non-empty string (URI or JSON)
    assert offer, "Credential offer must not be empty"

    # Should be a URL beginning with openid-credential-offer:// or a JSON string
    if isinstance(offer, str):
        assert offer.startswith("openid-credential-offer://") or offer.startswith(
            "{"
        ), f"Offer string has unexpected format: {offer[:80]}"
    elif isinstance(offer, dict):
        assert "credential_issuer" in offer, (
            f"Offer dict missing credential_issuer: {offer}"
        )


# ---------------------------------------------------------------------------
# Step 4 — Credo offer resolution (debug endpoint)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_step4_credo_resolves_jwt_vc_offer(acapy_issuer_admin, credo_client):
    """Step 4: Credo can resolve a jwt_vc_json offer via /debug/resolve-offer.

    Checks that:
    - The endpoint returns 200
    - The resolved offer advertises jwt_vc_json format
    - We can see the binding methods and proof types the issuer advertises
    """
    suffix = str(uuid.uuid4())[:8]
    config = await _make_config(acapy_issuer_admin, suffix)
    result = await _make_offer(acapy_issuer_admin, config["supported_cred_id"])

    resp = await credo_client.post(
        "/debug/resolve-offer",
        json={"credential_offer": result["offer"]},
    )
    assert resp.status_code == 200, (
        f"/debug/resolve-offer returned {resp.status_code}: {resp.text}"
    )

    data = resp.json()
    configs = data.get("offered_configurations", {})
    assert configs, f"No offered_configurations in resolve response: {data}"

    formats = [c.get("format") for c in configs.values()]
    assert JWT_VC_FORMAT in formats, (
        f"Expected jwt_vc_json in offered formats, got: {formats}\n"
        f"Full configurations: {configs}"
    )

    # Log binding methods for visibility
    for cfg_id, cfg in configs.items():
        binding = cfg.get("cryptographic_binding_methods_supported")
        proof_types = cfg.get("proof_types_supported")
        print(
            f"\n[debug] config={cfg_id} format={cfg.get('format')}"
            f" binding={binding} proof_types={proof_types}"
        )


# ---------------------------------------------------------------------------
# Step 5 — Credo credential acceptance: binding resolver inspection
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_step5_credo_accept_offer_no_request_error(
    acapy_issuer_admin, credo_client
):
    """Step 5: requestCredentials() does not throw for jwt_vc_json.

    The Credo debug endpoint returns request_error=null when the full
    requestCredentials() call succeeds.  If this fails it means the
    credential request itself errors out BEFORE ACA-Py issues anything —
    e.g. because JWK binding is rejected for this format.
    """
    suffix = str(uuid.uuid4())[:8]
    config = await _make_config(acapy_issuer_admin, suffix)
    result = await _make_offer(acapy_issuer_admin, config["supported_cred_id"])

    resp = await credo_client.post(
        "/debug/accept-offer-inspect",
        json={"credential_offer": result["offer"]},
    )
    assert resp.status_code == 200, (
        f"/debug/accept-offer-inspect returned {resp.status_code}: {resp.text}"
    )

    data = resp.json()

    # Log binding resolver call details
    for call in data.get("binding_resolver_calls", []):
        print(
            f"\n[debug] binding resolver called with: format={call.get('credentialFormat')}"
            f" supportsJwk={call.get('supportsJwk')}"
            f" supportsAllDid={call.get('supportsAllDidMethods')}"
            f" supportedDidMethods={call.get('supportedDidMethods')}"
            f" proofAlgs={call.get('proof_type_algs')}"
            f" resolvedMethod={call.get('resolved_method')}"
        )

    assert data.get("request_error") is None, (
        f"requestCredentials() threw an error for jwt_vc_json:\n"
        f"  error: {data.get('request_error')}\n"
        f"  stack: {data.get('request_error_stack', '')[:400]}\n"
        f"  binding calls: {data.get('binding_resolver_calls')}"
    )


# ---------------------------------------------------------------------------
# Step 6 — Credo record structure inspection
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_step6_credo_returns_w3c_credential_record(
    acapy_issuer_admin, credo_client
):
    """Step 6: Credo returns a W3cCredentialRecord for jwt_vc_json.

    Dumps the full record structure so we can see exactly what keys/getters
    are available to extract the JWT string.
    """
    suffix = str(uuid.uuid4())[:8]
    config = await _make_config(acapy_issuer_admin, suffix)
    result = await _make_offer(acapy_issuer_admin, config["supported_cred_id"])

    resp = await credo_client.post(
        "/debug/accept-offer-inspect",
        json={"credential_offer": result["offer"]},
    )
    assert resp.status_code == 200

    data = resp.json()
    credentials = data.get("credentials", [])

    print(f"\n[debug] credentials_count={data.get('credentials_count')}")
    for i, cred in enumerate(credentials):
        print(f"\n[debug] credential[{i}]:")
        print(f"  constructor_name  = {cred.get('constructor_name')}")
        print(f"  record_type       = {cred.get('record_type')}")
        print(f"  own_keys          = {cred.get('own_keys')}")
        print(f"  prototype_keys    = {cred.get('prototype_keys')}")
        print(f"  instances_count   = {cred.get('credential_instances_count')}")
        print(f"  instances         = {cred.get('credential_instances')}")
        print(f"  getters           = {cred.get('getters')}")
        print(f"  serialized_keys   = {cred.get('serialized_keys')}")
        print(f"  serialized_inst   = {cred.get('serialized_instances')}")

    assert credentials, (
        "requestCredentials() succeeded but returned no credentials.\n"
        f"Full response: {data}"
    )

    rec = credentials[0]
    record_type = rec.get("constructor_name") or rec.get("record_type") or ""
    assert "W3c" in record_type or "w3c" in record_type.lower(), (
        f"Expected a W3cCredentialRecord, got constructor_name={rec.get('constructor_name')}"
        f" record_type={rec.get('record_type')}"
    )


# ---------------------------------------------------------------------------
# Step 7 — credentialInstances[0].credential is a JWT string
# ---------------------------------------------------------------------------


@pytest.mark.xfail(
    strict=False,
    reason=(
        "Credo 0.6.x masks compact JWTs behind W3cCredentialRecord getters "
        "(encoded='***').  The JWT is accessible via record._credential "
        "(issuance.ts Attempt 5); the debug endpoint exposes this as "
        "record_credential_raw.  If that field is also absent, the test is "
        "an expected failure — the real JWT check is in test_step9."
    ),
)
@pytest.mark.asyncio
async def test_step7_credential_instance_contains_jwt_string(
    acapy_issuer_admin, credo_client
):
    """Step 7: locate the compact JWT inside a W3cCredentialRecord.

    In Credo 0.6.x the JWT is stored behind multiple masking layers.
    This test probes every known path and passes if ANY path returns
    a valid JWT string.  The authoritative check is test_step9.
    """
    suffix = str(uuid.uuid4())[:8]
    config = await _make_config(acapy_issuer_admin, suffix)
    result = await _make_offer(acapy_issuer_admin, config["supported_cred_id"])

    resp = await credo_client.post(
        "/debug/accept-offer-inspect",
        json={"credential_offer": result["offer"]},
    )
    assert resp.status_code == 200

    data = resp.json()
    credentials = data.get("credentials", [])
    assert credentials, "No credentials returned by Credo"

    instances = credentials[0].get("credential_instances", [])
    assert instances, (
        "W3cCredentialRecord has no credential_instances.\n"
        f"Record info: {credentials[0]}"
    )

    inst = instances[0]
    print(f"\n[debug] instance[0] keys: {inst.get('own_keys')}")
    print(f"[debug] instance[0] all_values: {inst}")

    # Search for the JWT string across the candidate keys that issuance.ts Attempt 4
    # checks.  In Credo 0.6.x with did:key binding, the JWT is in inst.jwt.serializedJwt
    # (inst is a W3cJwtVerifiableCredential; inst.jwt is the parsed Jwt object).
    # debug.ts now exposes that as 'jwt_serializedJwt' on the instance dict.
    jwt_candidate_keys = [
        "serializedJwt",
        "compactJwtVc",
        "jwt",
        "credential",
        "encoded",
        "jwt_serializedJwt",  # Credo 0.6.x: inst.jwt.serializedJwt deep-drilled
        "jwt_compact",  # fallback alias
        "jwt_encoded",  # fallback alias
        "credential_jwt_serializedJwt",  # wrapper: inst.credential.jwt.serializedJwt
        "credential_jwt_compact",  # fallback alias
        "credential_jwt_encoded",  # fallback alias
    ]
    cred_val = None
    found_key = None
    for k in jwt_candidate_keys:
        v = inst.get(k)
        if isinstance(v, str) and v.startswith("ey") and "." in v:
            cred_val = v
            found_key = k
            break

    # Fallback: record.firstCredential.jwt.serializedJwt deep-drilled by debug.ts
    # and exposed as 'w3c_serialized_jwt' on the top-level credential dict.
    if cred_val is None:
        w3c = credentials[0].get("w3c_serialized_jwt", "")
        if isinstance(w3c, str) and w3c.startswith("ey") and "." in w3c:
            cred_val = w3c
            found_key = "w3c_serialized_jwt"

    # Fallback: check raw_oidc_credential exposed by the debug endpoint (Attempt 0
    # path in issuance.ts — the compact JWT from the OID4VCI response, before storage).
    if cred_val is None:
        raw = credentials[0].get("raw_oidc_credential", "")
        if isinstance(raw, str) and raw.startswith("ey") and "." in raw:
            cred_val = raw
            found_key = "raw_oidc_credential"

    # Fallback: record._credential private backing field (bypasses Credo masking).
    # debug.ts exposes this as 'record_credential_raw' if the underlying value
    # is an 'ey…' compact JWT string (issuance.ts Attempt 5 path).
    if cred_val is None:
        rc = credentials[0].get("record_credential_raw", "")
        if isinstance(rc, str) and rc.startswith("ey") and "." in rc:
            cred_val = rc
            found_key = "record_credential_raw"

    # Fallback: check record-level getters (issuance.ts Attempts 1/2/3/5 paths).
    if cred_val is None:
        getters = credentials[0].get("getters", {})
        for gk in ["encoded", "serializedJwt", "jwt"]:
            gv = getters.get(gk) if isinstance(getters, dict) else None
            if isinstance(gv, str) and gv.startswith("ey") and "." in gv:
                cred_val = gv
                found_key = f"getters.{gk}"
                break

    assert cred_val is not None, (
        f"No JWT string found in credentialInstances[0] under any candidate key "
        f"({jwt_candidate_keys}), nor in w3c_serialized_jwt, record_credential_raw, "
        f"raw_oidc_credential, nor in record getters.\n"
        f"  all_instance_keys       = {inst.get('own_keys')}\n"
        f"  all_values              = {inst}\n"
        f"  w3c_serialized_jwt      = {credentials[0].get('w3c_serialized_jwt')}\n"
        f"  record_credential_raw   = {credentials[0].get('record_credential_raw')}\n"
        f"  raw_oidc_credential     = {credentials[0].get('raw_oidc_credential')}\n"
        f"  getters                 = {credentials[0].get('getters')}"
    )
    print(f"[debug] Found JWT via key '{found_key}': {cred_val[:60]}…")


# ---------------------------------------------------------------------------
# Step 8 — Standard accept-offer returns non-null credential
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_step8_standard_accept_offer_returns_credential(
    acapy_issuer_admin, credo_client
):
    """Step 8: The standard /oid4vci/accept-offer endpoint returns a non-null credential.

    This is the call that the real revocation test makes.  If steps 1-7 pass
    but this fails, the extraction logic in issuance.ts needs updating.
    """
    suffix = str(uuid.uuid4())[:8]
    config = await _make_config(acapy_issuer_admin, suffix)
    result = await _make_offer(acapy_issuer_admin, config["supported_cred_id"])

    resp = await credo_client.post(
        "/oid4vci/accept-offer",
        json={"credential_offer": result["offer"]},
    )
    assert resp.status_code == 200, (
        f"/oid4vci/accept-offer returned {resp.status_code}: {resp.text}"
    )

    data = resp.json()
    print(
        f"\n[debug] accept-offer response: format={data.get('format')} "
        f"success={data.get('success')} "
        f"credential_type={type(data.get('credential')).__name__} "
        f"credential_preview={str(data.get('credential'))[:80]}"
    )

    assert data.get("credential") is not None, (
        "accept-offer returned credential=null.\n"
        "Check issuance.ts extraction logic for jwt_vc_json.\n"
        f"Full response: {data}"
    )


# ---------------------------------------------------------------------------
# Step 9 — Returned credential is a valid JWT
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_step9_returned_credential_is_valid_jwt(acapy_issuer_admin, credo_client):
    """Step 9: The returned credential is a properly-formed JWT string."""
    suffix = str(uuid.uuid4())[:8]
    config = await _make_config(acapy_issuer_admin, suffix)
    result = await _make_offer(acapy_issuer_admin, config["supported_cred_id"])

    resp = await credo_client.post(
        "/oid4vci/accept-offer",
        json={"credential_offer": result["offer"]},
    )
    assert resp.status_code == 200

    data = resp.json()
    credential = data.get("credential")
    assert credential is not None, "Credential is null; step 8 failed"

    assert isinstance(credential, str), (
        f"Expected credential to be a string, got {type(credential).__name__}: {credential}"
    )
    assert credential.startswith("ey"), (
        f"Credential does not look like a JWT (should start with 'ey'): {credential[:60]}"
    )
    parts = credential.split(".")
    assert len(parts) == 3, (
        f"JWT should have exactly 3 dot-separated parts, got {len(parts)}: {credential[:80]}"
    )

    # Decode and check shape
    payload = jwt.decode(credential, options={"verify_signature": False})
    print(f"\n[debug] JWT payload keys: {list(payload.keys())}")

    vc_body = payload.get("vc") or payload
    assert "type" in vc_body or "@type" in vc_body, (
        f"JWT payload missing 'type' field. Keys: {list(vc_body.keys())}"
    )
    assert "credentialSubject" in vc_body or "sub" in payload, (
        f"JWT payload missing credentialSubject. Keys: {list(vc_body.keys())}"
    )
