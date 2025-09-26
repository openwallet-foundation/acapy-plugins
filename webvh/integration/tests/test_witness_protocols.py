"""
Integration tests for witness protocols.
"""

import asyncio
import uuid

import pytest
from acapy_controller import Controller

from .constants import (
    CONTROLLER_ENV,
    TEST_NAMESPACE,
    WITNESS,
    WITNESS_KEY,
    WITNESS_KID,
    WITNESS_ID,
)


@pytest.mark.asyncio
async def test_self_witness_auto():
    witness = Controller(base_url=WITNESS)
    server_url = (await witness.get("/status/config"))["config"]["plugin_config"][
        "webvh"
    ]["server_url"]
    witness_config = await witness.post(
        "/did/webvh/configuration",
        json={
            "server_url": server_url,
            "witness_key": WITNESS_KEY,
            "witness": True,
            "auto_attest": True,
        },
    )
    assert witness_config["witnesses"][0] == WITNESS_ID

    # Ensure the witness key is properly configured
    response = await witness.get(f"/wallet/keys/{WITNESS_KEY}")
    assert WITNESS_KID in response["kid"] or response["kid"] == WITNESS_KID

    identifier = str(uuid.uuid4())
    create_response = await witness.post(
        "/did/webvh/create",
        json={
            "options": {
                "namespace": TEST_NAMESPACE,
                "identifier": identifier,
                "witnessThreshold": 1,
            }
        },
    )

    assert (did := create_response.get("state", {}).get("id"))
    assert identifier in did

    # Ensure no pending log entry is stored
    pending_log_entries = await witness.get("/did/webvh/witness-requests/log-entry")
    assert not pending_log_entries.get("results")

    # Confirm DID is published
    response = await witness.get(f"/resolver/resolve/{did}")
    assert response["did_document"]["id"] == did

    # Confirm DID is registered locally
    response = await witness.get(f"/wallet/did?did={did}")
    assert response.get("results")[0].get("did") == did


@pytest.mark.asyncio
async def test_self_witness_manual():
    witness = Controller(base_url=WITNESS)
    server_url = (await witness.get("/status/config"))["config"]["plugin_config"][
        "webvh"
    ]["server_url"]
    witness_config = await witness.post(
        "/did/webvh/configuration",
        json={
            "server_url": server_url,
            "witness_key": WITNESS_KEY,
            "witness": True,
            "auto_attest": False,
        },
    )
    assert witness_config["witnesses"][0] == WITNESS_ID

    # Ensure the witness key is properly configured
    response = await witness.get(f"/wallet/keys/{WITNESS_KEY}")
    assert WITNESS_KID in response["kid"] or response["kid"] == WITNESS_KID

    identifier = str(uuid.uuid4())
    create_response = await witness.post(
        "/did/webvh/create",
        json={
            "options": {
                "namespace": TEST_NAMESPACE,
                "identifier": identifier,
                "witnessThreshold": 1,
            }
        },
    )

    assert create_response.get("status") == "pending"

    pending_log_entries = await witness.get("/did/webvh/witness-requests/log-entry")
    log_entry = pending_log_entries.get("results", []).pop()
    assert isinstance(log_entry, dict)

    record_id = log_entry.get("record_id")
    await witness.post(f"/did/webvh/witness-requests/log-entry/{record_id}")
    await asyncio.sleep(3)

    # Confirm DID is published
    assert (did := log_entry["record"]["state"]["id"])
    response = await witness.get(f"/resolver/resolve/{did}")
    assert response["did_document"]["id"] == did

    # Confirm DID is registered
    response = await witness.get(f"/wallet/did?did={did}")
    assert response.get("results")[0].get("did") == did


@pytest.mark.asyncio
async def test_remote_witness_auto():
    controller = Controller(base_url=CONTROLLER_ENV)
    witness = Controller(base_url=WITNESS)
    server_url = (await witness.get("/status/config"))["config"]["plugin_config"][
        "webvh"
    ]["server_url"]
    witness_config = await witness.post(
        "/did/webvh/configuration",
        json={
            "server_url": server_url,
            "witness_key": WITNESS_KEY,
            "witness": True,
            "auto_attest": True,
        },
    )
    assert witness_config["witnesses"][0] == WITNESS_ID

    # Ensure the witness key is properly configured
    response = await witness.get(f"/wallet/keys/{WITNESS_KEY}")
    assert WITNESS_KID in response["kid"] or response["kid"] == WITNESS_KID

    # Create witness invitation
    invitation_url = (
        await witness.post(
            "did/webvh/witness-invitation",
            json={
                "alias": "controller",
                "label": "witness",
            },
        )
    )["invitation_url"]

    # Configure WebVH Controller
    await controller.post(
        "/did/webvh/configuration",
        json={
            "server_url": server_url,
            "witness": False,
            "witness_invitation": invitation_url,
        },
    )

    # Wait for the connection to be established
    await asyncio.sleep(1)

    # Create the initial did
    identifier = str(uuid.uuid4())
    create_response = await controller.post(
        "/did/webvh/create",
        json={
            "options": {
                "namespace": TEST_NAMESPACE,
                "identifier": identifier,
                "witnessThreshold": 1,
            }
        },
    )

    assert (did := create_response.get("state", {}).get("id"))
    assert identifier in did

    await asyncio.sleep(3)

    # Ensure no pending log entry is stored
    response = await witness.get("/did/webvh/witness-requests/log-entry")
    assert not response.get("results")

    # Confirm DID is published
    response = await witness.get(f"/resolver/resolve/{did}")
    assert response["did_document"]["id"] == did

    # Confirm DID is registered
    response = await controller.get(f"/wallet/did?did={did}")
    assert response.get("results")[0].get("did") == did


@pytest.mark.asyncio
async def test_remote_witness_manual():
    controller = Controller(base_url=CONTROLLER_ENV)
    witness = Controller(base_url=WITNESS)
    server_url = (await witness.get("/status/config"))["config"]["plugin_config"][
        "webvh"
    ]["server_url"]
    witness_config = await witness.post(
        "/did/webvh/configuration",
        json={
            "server_url": server_url,
            "witness_key": WITNESS_KEY,
            "witness": True,
            "auto_attest": False,
        },
    )
    assert witness_config["witnesses"][0] == WITNESS_ID

    # Ensure the witness key is properly configured
    response = await witness.get(f"/wallet/keys/{WITNESS_KEY}")
    assert WITNESS_KID in response["kid"] or response["kid"] == WITNESS_KID

    # Create witness invitation
    invitation_url = (
        await witness.post(
            "did/webvh/witness-invitation",
            json={
                "alias": "controller",
                "label": "witness",
            },
        )
    )["invitation_url"]

    # Configure WebVH Controller
    await controller.post(
        "/did/webvh/configuration",
        json={
            "server_url": server_url,
            "witness": False,
            "witness_invitation": invitation_url,
        },
    )

    # Wait for the connection to be established
    await asyncio.sleep(1)

    # Create the initial did
    identifier = str(uuid.uuid4())
    create_response = await controller.post(
        "/did/webvh/create",
        json={
            "options": {
                "namespace": TEST_NAMESPACE,
                "identifier": identifier,
                "witnessThreshold": 1,
            }
        },
    )

    await asyncio.sleep(3)

    pending_log_entries = await witness.get("/did/webvh/witness-requests/log-entry")
    log_entry = pending_log_entries.get("results", []).pop()
    assert isinstance(log_entry, dict)

    record_id = log_entry.get("record_id")
    await witness.post(f"/did/webvh/witness-requests/log-entry/{record_id}")
    await asyncio.sleep(3)

    # Confirm DID is published
    assert (did := log_entry["record"]["state"]["id"])
    response = await witness.get(f"/resolver/resolve/{did}")
    assert response["did_document"]["id"] == did

    # Confirm DID is registered
    response = await controller.get(f"/wallet/did?did={did}")
    assert response.get("results")[0].get("did") == did
