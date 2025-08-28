"""
Integration tests for the register DID protocol.
"""

import asyncio
import uuid

import pytest
from acapy_controller import Controller
from acapy_controller.controller import params

from .constants import (
    CONTROLLER_ENV,
    TEST_NAMESPACE,
    WITNESS,
    WITNESS_KEY,
    WITNESS_KID,
    WITNESS_ID,
)


@pytest.mark.asyncio
async def test_create_auto_self_witness():
    """Test Controller protocols."""
    async with (
        Controller(base_url=WITNESS) as witness,
    ):
        witness_config = (await witness.get("/status/config"))["config"]
        server_url = witness_config["plugin_config"]["did-webvh"]["server_url"]

        # Configure WebVH Witness
        await witness.post(
            "/did/webvh/configuration",
            json={
                "server_url": server_url,
                "witness_key": WITNESS_KEY,
                "witness": True,
                "auto_attest": True,
            },
        )

        # Ensure the witness key is properly configured
        response = await witness.get(f"/wallet/keys/{WITNESS_KEY}")
        assert WITNESS_KID in response["kid"] or response["kid"] == WITNESS_KID

        # Create the initial did
        identifier = str(uuid.uuid4())
        response = await witness.post(
            "/did/webvh/create",
            json={
                "options": {
                    "namespace": TEST_NAMESPACE,
                    "identifier": identifier,
                    "witnessThreshold": 1,
                }
            },
        )

        assert (did := response.get("state", {}).get("id"))
        assert identifier in did

        # Ensure no pending log entry is stored
        response = await witness.get("/did/webvh/witness/log-entries")
        assert not response.get("results")

        # Confirm DID is published
        response = await witness.get(f"/resolver/resolve/{did}")
        assert response["did_document"]["id"] == did

        # Confirm DID is registered
        response = await witness.get(f"/wallet/did?did={did}")
        assert response.get("results")[0].get("did") == did


@pytest.mark.asyncio
async def test_create_manual_self_witness():
    """Test Controller protocols."""
    async with Controller(base_url=WITNESS) as witness:
        witness_config = (await witness.get("/status/config"))["config"]
        server_url: str = witness_config["plugin_config"]["did-webvh"]["server_url"]

        # Configure WebVH Witness
        await witness.post(
            "/did/webvh/configuration",
            json={
                "server_url": server_url,
                "witness_key": WITNESS_KEY,
                "witness": True,
                "auto_attest": False,
            },
        )
        response = await witness.get(f"/wallet/keys/{WITNESS_KEY}")

        # Ensure the witness key is properly configured
        response = await witness.get(f"/wallet/keys/{WITNESS_KEY}")
        assert WITNESS_KID in response["kid"] or response["kid"] == WITNESS_KID

        # Create the initial did
        identifier = str(uuid.uuid4())
        response = await witness.post(
            "/did/webvh/create",
            json={
                "options": {
                    "namespace": TEST_NAMESPACE,
                    "identifier": identifier,
                    "witnessThreshold": 1,
                }
            },
        )

        assert response.get("status") == "pending"

        response = await witness.get("/did/webvh/witness/log-entries")
        entry = response.get("results", []).pop()
        assert isinstance(entry, dict)

        await witness.post(
            "/did/webvh/witness/log-entries",
            params=params(record_id=entry.get("record_id")),
        )
        await asyncio.sleep(3)

        # Confirm DID is published
        assert (did := entry["record"]["state"]["id"])
        response = await witness.get(f"/resolver/resolve/{did}")
        assert response["did_document"]["id"] == did

        # Confirm DID is registered
        response = await witness.get(f"/wallet/did?did={did}")
        assert response.get("results")[0].get("did") == did


@pytest.mark.asyncio
async def test_create_auto_remote_witness():
    """Test Controller protocols."""
    async with (
        Controller(base_url=WITNESS) as witness,
        Controller(base_url=CONTROLLER_ENV) as controller,
    ):
        witness_config = (await witness.get("/status/config"))["config"]
        server_url: str = witness_config["plugin_config"]["did-webvh"]["server_url"]

        # Configure WebVH Witness
        response = await witness.post(
            "/did/webvh/configuration",
            json={
                "server_url": server_url,
                "witness_key": WITNESS_KEY,
                "witness": True,
                "auto_attest": True,
            },
        )
        assert response["witnesses"][0] == WITNESS_ID

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
        response = await controller.post(
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
        response = await controller.post(
            "/did/webvh/create",
            json={
                "options": {
                    "namespace": TEST_NAMESPACE,
                    "identifier": identifier,
                    "witnessThreshold": 1,
                }
            },
        )

        assert (did := response.get("state", {}).get("id"))
        assert identifier in did

        await asyncio.sleep(3)

        # Ensure no pending log entry is stored
        response = await witness.get("/did/webvh/witness/log-entries")
        assert not response.get("results")

        # Confirm DID is published
        response = await witness.get(f"/resolver/resolve/{did}")
        assert response["did_document"]["id"] == did

        # Confirm DID is registered
        response = await controller.get(f"/wallet/did?did={did}")
        assert response.get("results")[0].get("did") == did


@pytest.mark.asyncio
async def test_create_manual_remote_witness():
    """Test Controller protocols."""
    async with (
        Controller(base_url=WITNESS) as witness,
        Controller(base_url=CONTROLLER_ENV) as controller,
    ):
        witness_config = (await witness.get("/status/config"))["config"]
        server_url: str = witness_config["plugin_config"]["did-webvh"]["server_url"]

        # Configure WebVH Witness
        response = await witness.post(
            "/did/webvh/configuration",
            json={
                "server_url": server_url,
                "witness_key": WITNESS_KEY,
                "witness": True,
                "auto_attest": False,
            },
        )
        assert response["witnesses"][0] == WITNESS_ID

        # Ensure the witness key is properly configured
        response = await witness.get(f"/wallet/keys/{WITNESS_KEY}")
        assert WITNESS_KID in response["kid"] or response["kid"] == WITNESS_KID

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
        response = await controller.post(
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
        response = await controller.post(
            "/did/webvh/create",
            json={
                "options": {
                    "namespace": TEST_NAMESPACE,
                    "identifier": identifier,
                    "witnessThreshold": 1,
                }
            },
        )

        assert response.get("status") == "pending"

        response = await witness.get("/did/webvh/witness/log-entries")
        entry = response.get("results", []).pop()
        assert isinstance(entry, dict)

        await witness.post(
            "/did/webvh/witness/log-entries",
            params=params(record_id=entry.get("record_id")),
        )
        await asyncio.sleep(3)

        # Confirm DID is published
        assert (did := entry["record"]["state"]["id"])
        response = await witness.get(f"/resolver/resolve/{did}")
        assert response["did_document"]["id"] == did

        # Confirm DID is registered
        response = await controller.get(f"/wallet/did?did={did}")
        assert response.get("results")[0].get("did") == did
