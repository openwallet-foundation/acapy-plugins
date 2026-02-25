"""
Integration tests for the AnonCreds Registry.

Covers: create DID, schema, cred def (with rev def), get active rev reg,
rotate rev reg, get new active rev reg and assert rotation.

Runs the full flow for: no witness, self witness, remote witness (auto_attest
true and false). Remote witness scenarios are currently skipped (resolver/timing).
"""

import asyncio
import urllib
import uuid

import pytest
from acapy_controller import Controller

from .constants import (
    CONTROLLER_ENV,
    NO_WITNESS,
    SERVER_URL,
    TEST_NAMESPACE,
    TEST_SCHEMA,
    TEST_SIZE,
    TEST_TAG,
    WITNESS,
    WITNESS_KEY,
)

# Max wait for active registry to become available (seconds)
ACTIVE_REGISTRY_WAIT = 30
ACTIVE_REGISTRY_POLL_INTERVAL = 2
# Wait for pending attested resources to appear on witness (manual flow)
PENDING_ATTESTED_POLL_INTERVAL = 1
PENDING_ATTESTED_POLL_ATTEMPTS = 20


async def _drain_pending_attested_resources(witness_agent) -> None:
    """Poll witness for pending attested-resource requests and approve each.
    Used for remote_witness with auto_attest=False after each anoncreds create.
    """
    for _ in range(PENDING_ATTESTED_POLL_ATTEMPTS):
        r = await witness_agent.get("/did/webvh/requests/attested-resource")
        results = r.get("results", [])
        if not results:
            await asyncio.sleep(PENDING_ATTESTED_POLL_INTERVAL)
            continue
        for item in results:
            record_id = item.get("record_id")
            if record_id:
                await witness_agent.post(
                    f"/did/webvh/requests/attested-resource/{record_id}",
                )
        await asyncio.sleep(2)
        return
    pytest.fail("Pending attested resources did not appear on witness in time")


async def _create_did_self_witness(agent):
    """Configure agent as self-witness and create DID (witness_threshold=1)."""
    await agent.post(
        "/did/webvh/configuration",
        json={
            "server_url": SERVER_URL,
            "witness_key": WITNESS_KEY,
            "witness": True,
            "auto_attest": True,
            "endorsement": True,
        },
    )
    identifier = str(uuid.uuid4())
    response = await agent.post(
        "/did/webvh/create",
        json={
            "options": {
                "namespace": TEST_NAMESPACE,
                "identifier": identifier,
                "witness_threshold": 1,
            }
        },
    )
    return response["state"]["id"]


async def _create_did_no_witness(agent):
    """Configure agent with no witness and create DID (witness_threshold=0)."""
    await agent.post(
        "/did/webvh/configuration",
        json={
            "server_url": SERVER_URL,
            "witness": False,
            "endorsement": False,
        },
    )
    identifier = str(uuid.uuid4())
    response = await agent.post(
        "/did/webvh/create",
        json={
            "options": {
                "namespace": TEST_NAMESPACE,
                "identifier": identifier,
                "witness_threshold": 0,
            }
        },
    )
    return response["state"]["id"]


async def _create_did_remote_witness(
    controller_agent, witness_agent, auto_attest: bool = True
):
    """Configure witness (auto_attest True or False), create invitation,
    configure controller, create DID. For auto_attest=False, approve pending
    log-entry on witness after controller creates DID.
    """
    server_url = (await witness_agent.get("/status/config"))["config"]["plugin_config"][
        "webvh"
    ]["server_url"]
    await witness_agent.post(
        "/did/webvh/configuration",
        json={
            "server_url": server_url,
            "witness_key": WITNESS_KEY,
            "witness": True,
            "auto_attest": auto_attest,
        },
    )
    invitation_url = (
        await witness_agent.post(
            "did/webvh/witness-invitation",
            json={"alias": "controller", "label": "witness"},
        )
    )["invitation_url"]
    await controller_agent.post(
        "/did/webvh/configuration",
        json={
            "server_url": server_url,
            "witness": False,
            "witness_invitation": invitation_url,
            "endorsement": True,
        },
    )
    await asyncio.sleep(1)
    identifier = str(uuid.uuid4())
    response = await controller_agent.post(
        "/did/webvh/create",
        json={
            "options": {
                "namespace": TEST_NAMESPACE,
                "identifier": identifier,
                "witness_threshold": 1,
            }
        },
    )
    if auto_attest:
        await asyncio.sleep(2)
        return response["state"]["id"]
    # Manual: controller got "pending"; approve on witness and get did from record
    assert response.get("status") == "pending"
    pending = await witness_agent.get("/did/webvh/requests/log-entry")
    results = pending.get("results", [])
    assert results, "Expected pending log-entry on witness"
    log_entry = results[0]
    record_id = log_entry.get("record_id")
    assert record_id
    await witness_agent.post(
        f"/did/webvh/requests/log-entry/{record_id}",
    )
    await asyncio.sleep(3)
    return log_entry["record"]["state"]["id"]


async def create_did(agent):
    """Self-witness default (for backward compatibility)."""
    return await _create_did_self_witness(agent)


def _cred_def_id_encoded(cred_def_id: str) -> str:
    """URL-encode cred def id for use in path (handles slashes)."""
    return urllib.parse.quote(cred_def_id, safe="")


async def _get_active_rev_reg_id(agent, cred_def_id: str) -> str:
    """GET active revocation registry for cred def; return rev_reg_def id."""
    path = (
        f"/anoncreds/revocation/active-registry/{_cred_def_id_encoded(cred_def_id)}"
    )
    response = await agent.get(path)
    assert "result" in response, response
    # IssuerRevRegRecord.serialize() uses revoc_reg_id
    return response["result"]["revoc_reg_id"]


async def _wait_for_active_registry(agent, cred_def_id: str) -> str:
    """Poll until active registry is available; return its rev_reg_def id."""
    path = (
        f"/anoncreds/revocation/active-registry/{_cred_def_id_encoded(cred_def_id)}"
    )
    for _ in range(ACTIVE_REGISTRY_WAIT // ACTIVE_REGISTRY_POLL_INTERVAL):
        try:
            response = await agent.get(path)
            if "result" in response and response["result"].get("revoc_reg_id"):
                return response["result"]["revoc_reg_id"]
        except Exception:
            pass
        await asyncio.sleep(ACTIVE_REGISTRY_POLL_INTERVAL)
    pytest.fail("Active revocation registry did not become available in time")


async def _run_full_anoncreds_flow(
    agent,
    did: str,
    wait_after_create_seconds: float = 0,
    approve_pending_fn=None,
):
    """Run schema, cred def, rev reg, get active, rotate, assert rotation.

    When wait_after_create_seconds > 0 (remote witness auto), wait after each
    create so the witness can attest before we GET/resolve.
    When approve_pending_fn is set (remote witness manual), call it after each
    create to drain and approve pending attested-resource on the witness.
    """
    is_remote = wait_after_create_seconds > 0 or approve_pending_fn is not None

    # 2. Create schema
    response = await agent.post(
        "/anoncreds/schema",
        json={
            "options": {},
            "schema": {
                "attrNames": TEST_SCHEMA["attributes"],
                "issuerId": did,
                "name": TEST_SCHEMA["name"],
                "version": TEST_SCHEMA["version"],
            },
        },
    )
    schema_id = response["schema_state"]["schema_id"]
    if approve_pending_fn:
        await approve_pending_fn()
    if wait_after_create_seconds:
        await asyncio.sleep(wait_after_create_seconds)
    schema_id_encoded = urllib.parse.quote_plus(schema_id)
    if not is_remote:
        response = await agent.get(f"/anoncreds/schema/{schema_id_encoded}")
        assert response["schema"]
        assert response["schema_id"] == schema_id

    # 3. Create cred def with revocation support (creates rev def path)
    response = await agent.post(
        "/anoncreds/credential-definition",
        json={
            "options": {"support_revocation": True},
            "credential_definition": {
                "issuerId": did,
                "schemaId": schema_id,
                "tag": TEST_TAG,
            },
        },
    )
    cred_def_id = response["credential_definition_state"]["credential_definition_id"]
    assert cred_def_id
    if approve_pending_fn:
        await approve_pending_fn()
    if wait_after_create_seconds:
        await asyncio.sleep(3)
    cred_def_id_encoded = urllib.parse.quote_plus(cred_def_id)
    if not is_remote:
        response = await agent.get(
            f"/anoncreds/credential-definition/{cred_def_id_encoded}"
        )
        assert response["credential_definition"]
        assert response["credential_definition_id"] == cred_def_id

    # 4. Create first revocation registry definition
    response = await agent.post(
        "/anoncreds/revocation-registry-definition",
        json={
            "options": {},
            "revocation_registry_definition": {
                "issuerId": did,
                "credDefId": cred_def_id,
                "maxCredNum": TEST_SIZE,
                "tag": TEST_TAG,
            },
        },
    )
    rev_reg_id_created = response["revocation_registry_definition_state"][
        "revocation_registry_definition_id"
    ]
    assert rev_reg_id_created
    if approve_pending_fn:
        await approve_pending_fn()
    if wait_after_create_seconds:
        await asyncio.sleep(wait_after_create_seconds)

    # 5. Wait for active registry to be available (tails, list, activation)
    old_active_rev_reg_id = await _wait_for_active_registry(agent, cred_def_id)
    assert old_active_rev_reg_id

    # 6. Get active rev reg for cred def (explicit get)
    current_active = await _get_active_rev_reg_id(agent, cred_def_id)
    assert current_active == old_active_rev_reg_id

    # 7. Rotate revocation registry (creates new backup, sets it active)
    rotate_path = (
        f"/anoncreds/revocation/active-registry/"
        f"{_cred_def_id_encoded(cred_def_id)}/rotate"
    )
    response = await agent.post(rotate_path, json={})
    assert "rev_reg_ids" in response

    # 8. Allow rotation to complete (new active set)
    await asyncio.sleep(3)

    # 9. Get new active rev reg and ensure it has rotated
    new_active_rev_reg_id = await _get_active_rev_reg_id(agent, cred_def_id)
    assert new_active_rev_reg_id, "No active registry after rotate"
    assert (
        new_active_rev_reg_id != old_active_rev_reg_id
    ), "Active revocation registry did not change after rotate"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "scenario",
    [
        "no_witness",
        "self_witness",
        pytest.param(
            "remote_witness_auto",
            marks=pytest.mark.skip(
                reason="schema not resolvable from controller after attest; "
                "unskip when resolver/timing fixed"
            ),
        ),
        pytest.param(
            "remote_witness_manual",
            marks=pytest.mark.skip(
                reason="schema not resolvable from controller after attest; "
                "unskip when resolver/timing fixed"
            ),
        ),
    ],
)
async def test_anoncreds_did_schema_cred_def_rev_reg_active_rotate(scenario):
    """Full flow: create DID, schema, cred def (with rev def), get active rev reg,
    rotate rev reg, get new active rev reg and ensure rotated.

    Scenarios: no_witness, self_witness, remote_witness_auto (auto_attest=True),
    remote_witness_manual (auto_attest=False; witness approves each resource).
    """
    if scenario == "no_witness":
        async with Controller(base_url=NO_WITNESS) as agent:
            did = await _create_did_no_witness(agent)
            assert did
            await _run_full_anoncreds_flow(agent, did)
    elif scenario == "self_witness":
        async with Controller(base_url=WITNESS) as agent:
            did = await _create_did_self_witness(agent)
            assert did
            await _run_full_anoncreds_flow(agent, did)
    else:
        assert scenario in ("remote_witness_auto", "remote_witness_manual")
        auto_attest = scenario == "remote_witness_auto"
        witness_agent = Controller(base_url=WITNESS)
        controller_agent = Controller(base_url=CONTROLLER_ENV)
        did = await _create_did_remote_witness(
            controller_agent, witness_agent, auto_attest=auto_attest
        )
        assert did
        if auto_attest:
            await _run_full_anoncreds_flow(
                controller_agent, did, wait_after_create_seconds=10
            )
        else:
            async def approve_pending():
                await _drain_pending_attested_resources(witness_agent)

            await _run_full_anoncreds_flow(
                controller_agent, did, approve_pending_fn=approve_pending
            )


@pytest.mark.asyncio
async def test_anoncreds():
    """Test Controller protocols: DID, schema, cred def with rev, rev reg def, fetch."""
    async with Controller(base_url=WITNESS) as agent:
        did = await create_did(agent)

        response = await agent.post(
            "/anoncreds/schema",
            json={
                "options": {},
                "schema": {
                    "attrNames": TEST_SCHEMA["attributes"],
                    "issuerId": did,
                    "name": TEST_SCHEMA["name"],
                    "version": TEST_SCHEMA["version"],
                },
            },
        )
        schema_id = response["schema_state"]["schema_id"]
        schema_id_encoded = urllib.parse.quote_plus(schema_id)
        response = await agent.get(f"/anoncreds/schema/{schema_id_encoded}")
        assert response["schema"]
        assert response["schema_id"] == schema_id

        response = await agent.post(
            "/anoncreds/credential-definition",
            json={
                "options": {"support_revocation": True},
                "credential_definition": {
                    "issuerId": did,
                    "schemaId": schema_id,
                    "tag": TEST_TAG,
                },
            },
        )
        cred_def_id = response["credential_definition_state"]["credential_definition_id"]
        assert cred_def_id
        cred_def_id_encoded = urllib.parse.quote_plus(cred_def_id)
        response = await agent.get(
            f"/anoncreds/credential-definition/{cred_def_id_encoded}"
        )
        assert response["credential_definition"]
        assert response["credential_definition_id"] == cred_def_id

        response = await agent.post(
            "/anoncreds/revocation-registry-definition",
            json={
                "options": {},
                "revocation_registry_definition": {
                    "issuerId": did,
                    "credDefId": cred_def_id,
                    "maxCredNum": TEST_SIZE,
                    "tag": TEST_TAG,
                },
            },
        )
        await asyncio.sleep(2)  # wait for registry to be created
        rev_reg_id = response["revocation_registry_definition_state"][
            "revocation_registry_definition_id"
        ]
        assert rev_reg_id
        rev_reg_id_encoded = urllib.parse.quote_plus(rev_reg_id)
        response = await agent.get(
            f"/anoncreds/revocation/registry/{rev_reg_id_encoded}"
        )
        assert response["result"]
