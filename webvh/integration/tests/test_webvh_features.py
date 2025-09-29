"""
Integration tests for WebVH features.
"""

import uuid

import pytest

from acapy_controller import Controller
from .constants import CONTROLLER_ENV, TEST_NAMESPACE, WITNESS, WITNESS_KEY


@pytest.mark.asyncio
async def test_prerotation():
    """Test prerotation."""
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
                "prerotation": True,
            }
        },
    )

    assert (did_document := create_response.get("state", {}))
    assert (did := did_document.get("id"))
    assert (scid := did.split(":")[2])

    # TODO, webvh server has a bug, will be fixed in version 0.3.4
    # did_document["alsoKnownAs"] = ["https://example.com/updated"]

    # await witness.post(
    #     f"/did/webvh/update?scid={scid}",
    #     json={"did_document": did_document, "options": {}},
    # )

    # await asyncio.sleep(3)  # Allow time for the update to propagate
    # response = await controller.get(f"/resolver/resolve/{did}")
    # assert response["did_document"]["id"] == did
    # assert response["did_document"]["alsoKnownAs"] == ["https://example.com/updated"]


@pytest.mark.asyncio
async def test_portability():
    """Test portability."""
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
                "portability": True,
            }
        },
    )

    assert (did_document := create_response.get("state", {}))
    assert (did := did_document.get("id"))


@pytest.mark.asyncio
async def test_watcher():
    """Test watcher."""
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
            "notify_watchers": True,
        },
    )

    identifier = str(uuid.uuid4())
    create_response = await witness.post(
        "/did/webvh/create",
        json={
            "options": {
                "namespace": TEST_NAMESPACE,
                "identifier": identifier,
                "watcher": "https://example.com",
            }
        },
    )

    assert (did_document := create_response.get("state", {}))
    assert (did := did_document.get("id"))


@pytest.mark.asyncio
async def test_whois():
    """Test whois."""
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
            "notify_watchers": True,
        },
    )

    identifier = str(uuid.uuid4())
    create_response = await witness.post(
        "/did/webvh/create",
        json={
            "options": {
                "namespace": TEST_NAMESPACE,
                "identifier": identifier,
            }
        },
    )

    assert (did_document := create_response.get("state", {}))
    assert (did := did_document.get("id"))
    assert (scid := did.split(":")[2])
    credential = (
        await witness.post(
            "/vc/di/add-proof",
            json={
                "document": {
                    "@context": [
                        "https://www.w3.org/ns/credentials/v2",
                        "https://www.w3.org/ns/credentials/examples/v2",
                    ],
                    "type": ["VerifiableCredential", "ExampleWhoisCredential"],
                    "name": "Example Whois Credential",
                    "description": "An example credential to illustrate DID WHOIS functionality",
                    "issuer": {
                        "id": f"did:key:{WITNESS_KEY}",
                        "name": "Example Issuer",
                        "image": "https://example.com/logo.png",
                    },
                    "credentialSubject": {
                        "id": did,
                        "name": "Test Subject",
                        "description": "Example Whois Credential Subject",
                    },
                },
                "options": {
                    "type": "DataIntegrityProof",
                    "cryptosuite": "eddsa-jcs-2022",
                    "proofPurpose": "assertionMethod",
                    "verificationMethod": f"did:key:{WITNESS_KEY}#{WITNESS_KEY}",
                },
            },
        )
    ).get("securedDocument")
    response = await witness.post(
        f"/did/webvh/whois?scid={scid}",
        json={
            "presentation": {
                "@context": [
                    "https://www.w3.org/ns/credentials/v2",
                    "https://www.w3.org/ns/credentials/examples/v2",
                ],
                "type": ["VerifiablePresentation"],
                "holder": did,
                "verifiableCredential": [credential],
            }
        },
    )
    assert response


@pytest.mark.asyncio
async def test_witness():
    """Test witness."""
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
