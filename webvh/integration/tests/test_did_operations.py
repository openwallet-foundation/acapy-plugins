"""
Integration tests for DID operations.
"""

import asyncio
import uuid

import pytest
from acapy_controller import Controller

from .constants import CONTROLLER_ENV, TEST_NAMESPACE, WITNESS, WITNESS_KEY


@pytest.mark.asyncio
async def test_create_operation():
    """Test DID Create operation."""
    witness = Controller(base_url=WITNESS)
    server_url = (await witness.get("/status/config"))["config"]["plugin_config"][
        "webvh"
    ]["server_url"]
    await witness.post(
        "/did/webvh/configuration",
        json={
            "server_url": server_url,
            "witness_key": WITNESS_KEY,
            "witness": True,
            "auto_attest": True,
        },
    )

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

    response = await witness.get(f"/resolver/resolve/{did}")
    assert response["did_document"]["id"] == did


@pytest.mark.asyncio
async def test_update_operation():
    """Test DID Update operation."""
    controller = Controller(base_url=CONTROLLER_ENV)
    witness = Controller(base_url=WITNESS)
    server_url = (await witness.get("/status/config"))["config"]["plugin_config"][
        "webvh"
    ]["server_url"]
    await witness.post(
        "/did/webvh/configuration",
        json={
            "server_url": server_url,
            "witness_key": WITNESS_KEY,
            "witness": True,
            "auto_attest": True,
        },
    )

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

    assert (did_document := create_response.get("state", {}))
    assert (did := did_document.get("id"))
    assert (scid := did.split(":")[2])

    did_document["alsoKnownAs"] = ["https://example.com/updated"]

    await witness.post(
        f"/did/webvh/update?scid={scid}",
        json={"did_document": did_document, "options": {}},
    )

    await asyncio.sleep(3)  # Allow time for the update to propagate
    response = await controller.get(f"/resolver/resolve/{did}")
    assert response["did_document"]["id"] == did
    assert response["did_document"]["alsoKnownAs"] == ["https://example.com/updated"]


@pytest.mark.asyncio
async def test_deactivate_operation():
    """Test DID Deactivate operation."""
    witness = Controller(base_url=WITNESS)
    controller = Controller(base_url=CONTROLLER_ENV)
    server_url = (await witness.get("/status/config"))["config"]["plugin_config"][
        "webvh"
    ]["server_url"]
    await witness.post(
        "/did/webvh/configuration",
        json={
            "server_url": server_url,
            "witness_key": WITNESS_KEY,
            "witness": True,
            "auto_attest": True,
        },
    )

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
    assert (scid := did.split(":")[2])

    deactivate_response = await witness.post(
        f"/did/webvh/deactivate?scid={scid}", json={"options": {}}
    )

    await asyncio.sleep(3)  # Allow time for the deactivation to propagate
    response = await controller.get(f"/resolver/resolve/{did}")
    assert response["did_document"]["id"] == did
    assert response["did_document"].get("verificationMethod", []) == []
