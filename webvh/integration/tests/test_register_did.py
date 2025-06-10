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
    WEBVH_DOMAIN,
    WITNESS,
    WITNESS_KEY,
    WITNESS_KID,
)


@pytest.mark.asyncio
async def test_create_single_tenant():
    """Test Controller protocols."""
    async with (
        Controller(base_url=WITNESS) as witness,
    ):
        witness_config = (await witness.get("/status/config"))["config"]
        server_url = witness_config["plugin_config"]["did-webvh"]["server_url"]

        # Assign kid to witness key
        try:
            await witness.put(
                "/wallet/keys",
                json={
                    "multikey": WITNESS_KEY,
                    "kid": WITNESS_KID,
                },
            )
        except Exception:
            pass

        # Ensure the witness key is properly configured
        response = await witness.get(f"/wallet/keys/{WITNESS_KEY}")
        assert response["kid"] == WITNESS_KID

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
        assert response["multikey"] == WITNESS_KEY

        # Ensure the witness key is properly configured
        response = await witness.get(f"/wallet/keys/{WITNESS_KEY}")
        assert response["kid"] == WITNESS_KID

        # Create the initial did
        identifier = str(uuid.uuid4())
        response = await witness.post(
            "/did/webvh/controller/create",
            json={"options": {"namespace": TEST_NAMESPACE, "identifier": identifier}},
        )

        _id = response.get("id")
        assert _id
        assert identifier in _id

        # Confirm DID is published
        did_web = f"did:web:{WEBVH_DOMAIN}:{TEST_NAMESPACE}:{identifier}"
        response = await witness.get(f"/resolver/resolve/{did_web}")
        assert response["did_document"]["id"] == did_web
        assert response["did_document"]["alsoKnownAs"][0].startswith("did:webvh:")


@pytest.mark.asyncio
async def test_create_with_witness_and_auto_attest():
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
        assert response["multikey"] == WITNESS_KEY

        invitation_url = (
            await witness.post(
                "did/webvh/witness/invitations",
                json={
                    "alias": "witness",
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

        # Ensure the witness key is properly configured
        response = await witness.get(f"/wallet/keys/{WITNESS_KEY}")
        assert response["kid"] == WITNESS_KID

        # Create the initial did
        identifier = str(uuid.uuid4())
        response = await controller.post(
            "/did/webvh/controller/create",
            json={"options": {"namespace": TEST_NAMESPACE, "identifier": identifier}},
        )

        _id = response.get("id")
        assert _id
        assert identifier in _id

        response = await witness.get("/did/webvh/witness/registrations")
        assert not response.get("results")

        await asyncio.sleep(1)

        # Confirm DID is published
        did_web = f"did:web:{WEBVH_DOMAIN}:{TEST_NAMESPACE}:{identifier}"
        response = await controller.get(f"/resolver/resolve/{did_web}")
        assert response["did_document"]["id"] == did_web
        assert response["did_document"]["alsoKnownAs"][0].startswith("did:webvh:")


@pytest.mark.asyncio
async def test_create_with_witness_and_manual_attest():
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
        assert response["multikey"] == WITNESS_KEY

        invitation_url = (
            await witness.post(
                "did/webvh/witness/invitations",
                json={
                    "alias": "witness",
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

        # Ensure the witness key is properly configured
        response = await witness.get(f"/wallet/keys/{WITNESS_KEY}")
        assert response["kid"] == WITNESS_KID

        # Create the initial did
        identifier = str(uuid.uuid4())
        response = await controller.post(
            "/did/webvh/controller/create",
            json={"options": {"namespace": TEST_NAMESPACE, "identifier": identifier}},
        )

        status = response.get("status")
        assert status == "pending"

        response = await witness.get("/did/webvh/witness/registrations")
        entry = response.get("results", []).pop()
        assert isinstance(entry, dict)

        await witness.post(
            "/did/webvh/witness/registrations",
            params=params(did=entry["id"]),
        )
        await asyncio.sleep(3)

        # Confirm DID is published
        response = await controller.get(f"/resolver/resolve/{entry['id']}")
        did_web = f"did:web:{WEBVH_DOMAIN}:{TEST_NAMESPACE}:{identifier}"
        assert response["did_document"]["id"] == did_web
        assert response["did_document"]["alsoKnownAs"][0].startswith("did:webvh:")


@pytest.mark.asyncio
async def test_create_self_witness_and_manual_attest():
    """Test Controller protocols."""
    async with Controller(base_url=WITNESS) as witness:
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
        assert response["multikey"] == WITNESS_KEY

        # Ensure the witness key is properly configured
        response = await witness.get(f"/wallet/keys/{WITNESS_KEY}")
        assert response["kid"] == WITNESS_KID

        # Create the initial did
        identifier = str(uuid.uuid4())
        response = await witness.post(
            "/did/webvh/controller/create",
            json={"options": {"namespace": TEST_NAMESPACE, "identifier": identifier}},
        )

        status = response.get("status")
        assert status == "pending"

        response = await witness.get("/did/webvh/witness/registrations")
        entry = response.get("results", []).pop()
        assert isinstance(entry, dict)

        await witness.post(
            "/did/webvh/witness/registrations",
            params=params(did=entry["id"]),
        )
        await asyncio.sleep(3)

        # Confirm DID is published
        response = await witness.get(f"/resolver/resolve/{entry['id']}")
        did_web = f"did:web:{WEBVH_DOMAIN}:{TEST_NAMESPACE}:{identifier}"
        assert response["did_document"]["id"] == did_web
        assert response["did_document"]["alsoKnownAs"][0].startswith("did:webvh:")
