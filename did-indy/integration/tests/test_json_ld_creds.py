import json
import logging
from typing import Any, Dict, Optional
from uuid import uuid4

import base58
from acapy_controller.controller import Controller, Mapping
from acapy_controller.logging import logging_to_stdout
from acapy_controller.models import (
    ConnRecord,
    InvitationRecord,
    OobRecord,
    V20CredExRecord,
    V20CredExRecordDetail,
    V20PresExRecord,
)
import pytest
import pytest_asyncio

from credo_wrapper import CredoWrapper


LOGGER = logging.getLogger("controller." + __name__)


@pytest_asyncio.fixture
async def conn(credo: CredoWrapper, controller: Controller):
    """Test OOB DIDExchange Protocol."""
    logging_to_stdout()
    invitation = await controller.post(
        "/out-of-band/create-invitation",
        json={
            "handshake_protocols": ["https://didcomm.org/didexchange/1.1"],
        },
        response=InvitationRecord,
    )
    assert invitation.invitation
    inviter_conn = (
        await controller.get(
            "/connections",
            params={"invitation_msg_id": invitation.invitation.id},
        )
    )["results"][0]

    assert invitation.invitation_url
    await credo.receive_invitation(invitation.invitation_url)
    inviter_oob_record = await controller.record_with_values(
        topic="out_of_band",
        record_type=OobRecord,
        connection_id=inviter_conn["connection_id"],
        state="done",
    )
    inviter_conn = await controller.record_with_values(
        topic="connections",
        rfc23_state="request-received",
        invitation_key=inviter_oob_record.our_recipient_key,
        timeout=10,
    )
    conn_id = inviter_conn["connection_id"]
    inviter_conn = await controller.post(
        f"/didexchange/{conn_id}/accept-request",
    )
    inviter_conn = await controller.record_with_values(
        topic="connections",
        connection_id=conn_id,
        rfc23_state="completed",
        record_type=ConnRecord,
    )
    yield inviter_conn


@pytest_asyncio.fixture
async def issuing_did(controller: Controller):
    res = (
        await controller.post(
            "/wallet/did/create",
            json={"method": "key", "options": {"key_type": "ed25519"}},
        )
    )["result"]
    assert res
    did = res["did"]
    yield did


async def jsonld_issue_credential(
    issuer: Controller,
    holder: CredoWrapper,
    issuer_connection_id: str,
    credential: Mapping[str, Any],
    preview: Mapping[str, Any],
    options: Mapping[str, Any],
):
    """Issue a JSON-LD Credential."""
    issuer_cred_ex = await issuer.post(
        "/issue-credential-2.0/send-offer",
        json={
            "auto_issue": False,
            "auto_remove": False,
            "comment": "Credential from minimal example",
            "trace": False,
            "connection_id": issuer_connection_id,
            "credential_preview": {
                "@type": "issue-credential/2.0/credential-preview",
                "attributes": [
                    {"name": key, "value": str(value)} for key, value in preview.items()
                ],
            },
            "filter": {
                "ld_proof": {
                    "credential": credential,
                    "options": options,
                }
            },
        },
        response=V20CredExRecord,
    )
    issuer_cred_ex_id = issuer_cred_ex.cred_ex_id

    event = await holder.notification_received("CredentialStateChanged")
    LOGGER.debug("Event: %s", json.dumps(event, indent=2))
    record = event["payload"]["credentialRecord"]
    await holder.credentials_accept_offer(record["id"])

    await issuer.record_with_values(
        topic="issue_credential_v2_0",
        cred_ex_id=issuer_cred_ex_id,
        state="request-received",
    )

    issuer_cred_ex = await issuer.post(
        f"/issue-credential-2.0/records/{issuer_cred_ex_id}/issue",
        json={},
        response=V20CredExRecordDetail,
    )

    issuer_cred_ex = await issuer.record_with_values(
        topic="issue_credential_v2_0",
        record_type=V20CredExRecord,
        cred_ex_id=issuer_cred_ex_id,
        state="done",
    )

    return issuer_cred_ex


@pytest.mark.asyncio
async def test_issue(issued_cred):
    """Issuance test."""


ED25519_PUB_MULTICODEC = b"\xed\x01"


def vm_to_did_key(vm: Dict[str, Any]) -> str:
    """Turn a verification method into a did:key."""
    if "Ed25519" not in vm["type"]:
        raise ValueError("Only Ed25519 vms supported")

    if "publicKeyBase58" in vm:
        key = base58.b58decode(vm["publicKeyBase58"])
        return "did:key:z" + base58.b58encode(ED25519_PUB_MULTICODEC + key).decode()

    if "publicKeyMultibase" in vm:
        material: str = vm["publicKeyMultibase"]
        if not material.startswith("z"):
            raise ValueError(f"Unsupported multibase encoding: {material[0]}")

        if not material.startswith("z6Mk"):
            # Not multicodec wrapped
            material = (
                "z"
                + base58.b58encode(
                    ED25519_PUB_MULTICODEC + base58.b58decode(material[1:])
                ).decode()
            )

        return "did:key:" + material

    raise ValueError("Expected publicKeyBase58 or publicKeyMultibase")


def dereference_vm(doc: Dict[str, Any], id: str) -> Optional[Dict[str, Any]]:
    """Dereference a verification method by ID from a doc."""
    if "verificationMethod" not in doc:
        raise ValueError("Expected verificationMethod in doc")

    vms = doc["verificationMethod"]
    if not isinstance(vms, list):
        raise TypeError("Expected verificationMethod to be a list")
    if not vms:
        raise ValueError("Expected non-empty verificationMethod in doc")

    for vm in vms:
        if not isinstance(vm, dict):
            raise TypeError(
                "Expected verificationMethod list to be homogenously objects, got "
                f"{type(vm).__name__}"
            )
        if "id" not in vm:
            raise ValueError("id missing from verification method")

        if vm["id"] == id:
            return vm

    return None


def get_auth_vm_from_doc(doc: Dict[str, Any]) -> Dict[str, Any]:
    """Extract an auth verification method from the doc."""
    if "authentication" not in doc:
        raise ValueError("Expected authentication relationship in doc")

    authn = doc["authentication"]
    if not authn:
        raise ValueError("Expected non-empty authentication relationship in doc")

    vm = authn[0]
    if isinstance(vm, str):
        vm = dereference_vm(doc, vm)
        if not vm:
            raise ValueError(f"Bad reference in authentication: {authn[0]}")
        return vm
    elif isinstance(vm, dict):
        return vm
    else:
        raise TypeError(
            "Unexpected type for value in authentication; expected "
            f"str or dict, got {type(vm).__name__}"
        )


async def derive_did_key(agent: Controller, did: str) -> str:
    """Derive a did:key from another DID."""
    resolved = await agent.get(f"/resolver/resolve/{did}")
    doc: Dict[str, Any] = resolved["did_document"]
    vm = get_auth_vm_from_doc(doc)
    return vm_to_did_key(vm)


@pytest_asyncio.fixture
async def issued_cred(
    credo: CredoWrapper, controller: Controller, conn: ConnRecord, indy_did: str
):
    """Load AFJ with an issued credential."""
    assert conn.their_did
    holder_did = await derive_did_key(controller, conn.their_did)
    vm = indy_did + "#assert"

    credential = {
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json",
            "https://w3id.org/security/suites/ed25519-2020/v1",
        ],
        "name": "JFF x vc-edu PlugFest 3 Interoperability",
        "id": "urn:uuid:8f0df0cc-b5ab-48fa-8bc8-1bac515008cb",
        "type": ["VerifiableCredential", "OpenBadgeCredential"],
        "issuer": {
            "type": ["Profile"],
            "id": indy_did,
            "name": "JFF x vc-edu PlugFest 3 Interoperability",
        },
        "issuanceDate": "2024-08-21T18:20:23Z",
        "credentialSubject": {
            "id": holder_did,
            "type": ["AchievementSubject"],
            "achievement": {
                "name": "JFF x vc-edu PlugFest 3 Interoperability",
                "description": "This wallet supports the use of W3C Verifiable Credentials and has demonstrated interoperability during the presentation request workflow during JFF x VC-EDU PlugFest 3.",
                "criteria": {
                    "type": "Criteria",
                    "narrative": "Wallet solution providers earned this badge by demonstrating interoperability during the presentation request workflow. This included successfully receiving a presentation request, allowing the holder to select at least two types of verifiable credentials to create a verifiable presentation, returning the presentation to the requester, and passing verification of the presentation and the included credentials.",
                },
                "image": {
                    "id": "https://w3c-ccg.github.io/vc-ed/plugfest-3-2023/images/JFF-VC-EDU-PLUGFEST3-badge-image.png",
                    "type": "Image",
                },
                "type": ["Achievement"],
                "id": "urn:uuid:53b3803c-8774-4697-a614-455588181966",
            },
        },
    }
    options = {
        "challenge": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
        "created": "2021-12-31T23:59:59Z",
        "domain": "https://example.com",
        "proofPurpose": "assertionMethod",
        "proofType": "Ed25519Signature2020",
        "verificationMethod": vm,
    }
    preview = {
        "type": ["AchievementSubject"],
        "id": holder_did,
    }
    yield await jsonld_issue_credential(
        controller, credo, conn.connection_id, credential, preview, options
    )


async def jsonld_present_proof(
    verifier: Controller,
    holder: CredoWrapper,
    verifier_connection_id: str,
    presentation_definition: Mapping[str, Any],
    domain: str,
    *,
    comment: Optional[str] = None,
):
    """Present an Indy credential using present proof v1."""
    verifier_pres_ex = await verifier.post(
        "/present-proof-2.0/send-request",
        json={
            "auto_verify": False,
            "comment": comment or "Presentation request from minimal",
            "connection_id": verifier_connection_id,
            "presentation_request": {
                "dif": {
                    "presentation_definition": presentation_definition,
                    "options": {"challenge": str(uuid4()), "domain": domain},
                },
            },
            "trace": False,
        },
        response=V20PresExRecord,
    )
    verifier_pres_ex_id = verifier_pres_ex.pres_ex_id

    event = await holder.notification_received("ProofStateChanged")
    LOGGER.debug("Event: %s", json.dumps(event, indent=2))
    record = event["payload"]["proofRecord"]
    await holder.proofs_accept_request(record["id"])

    await verifier.record_with_values(
        topic="present_proof_v2_0",
        record_type=V20PresExRecord,
        pres_ex_id=verifier_pres_ex_id,
        state="presentation-received",
    )
    verifier_pres_ex = await verifier.post(
        f"/present-proof-2.0/records/{verifier_pres_ex_id}/verify-presentation",
        json={},
        response=V20PresExRecord,
    )
    verifier_pres_ex = await verifier.record_with_values(
        topic="present_proof_v2_0",
        record_type=V20PresExRecord,
        pres_ex_id=verifier_pres_ex_id,
        state="done",
    )

    return verifier_pres_ex


@pytest.mark.asyncio
async def test_present(
    credo: CredoWrapper,
    controller: Controller,
    conn: ConnRecord,
    issued_cred: V20CredExRecord,
):
    """Test a presentation."""
    definition = {
        "id": str(uuid4()),
        "input_descriptors": [
            {
                "id": "achievement",
                "name": "PlugFest interop",
                "schema": [
                    {
                        "uri": "https://www.w3.org/2018/credentials#VerifiableCredential"  # noqa: E501
                    },
                    {
                        "uri": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#OpenBadgeCredential"  # noqa: E501
                    },
                    {
                        "uri": "https://www.w3.org/2018/credentials/v1",
                    },
                ],
                "constraints": {
                    "is_holder": [
                        {
                            "directive": "required",
                            "field_id": ["1f44d55f-f161-4938-a659-f8026467f126"],
                        }
                    ],
                    "fields": [
                        {
                            "id": "1f44d55f-f161-4938-a659-f8026467f126",
                            "path": ["$.credentialSubject.achievement"],
                            "purpose": "Verify achievement",  # noqa: E501
                        },
                    ],
                },
            }
        ],
        "format": {"ldp_vp": {"proof_type": ["Ed25519Signature2020"]}},
    }
    record = await jsonld_present_proof(
        controller, credo, conn.connection_id, definition, "test-domain"
    )
    assert record.verified == "true"
