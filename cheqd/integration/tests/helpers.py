import json
from dataclasses import dataclass
from typing import Mapping, Optional, Tuple

from acapy_controller import Controller
from acapy_controller.controller import Minimal


@dataclass
class V20CredExRecord(Minimal):
    """V2.0 credential exchange record."""

    state: str
    cred_ex_id: str
    connection_id: str
    thread_id: str


@dataclass
class V20CredExRecordFormat(Minimal):
    """V2.0 credential exchange record anoncreds."""

    rev_reg_id: Optional[str] = None
    cred_rev_id: Optional[str] = None


@dataclass
class V20CredExRecordDetail(Minimal):
    """V2.0 credential exchange record detail."""

    cred_ex_record: V20CredExRecord
    details: Optional[V20CredExRecordFormat] = None


def format_json(json_to_format):
    """Pretty print json."""
    return json.dumps(json_to_format, indent=4)


async def create_did(issuer):
    """Create a DID on the Cheqd testnet."""
    did_create_result = await issuer.post("/did/cheqd/create")
    did = did_create_result.get("did")

    assert did, "DID creation failed."
    assert did_create_result.get("verkey"), "Verkey is missing in DID creation result."

    print(f"Created DID: {did}")
    return did


async def resolve_did(issuer, did):
    """Resolve the DID document."""
    resolution_result = await issuer.get(f"/resolver/resolve/{did}")
    did_document = resolution_result.get("did_document")

    assert did_document, "DID document resolution failed."
    print(f"Resolved DID Document: {format_json(did_document)}")
    return did_document


async def update_did(issuer, did, did_document):
    """Update the DID document by adding a service endpoint."""
    service = [
        {
            "id": f"{did}#service-1",
            "type": "MessagingService",
            "serviceEndpoint": ["https://example.com/service"],
        }
    ]
    did_document["service"] = service
    del did_document["@context"]

    did_update_result = await issuer.post(
        "/did/cheqd/update", json={"did": did, "didDocument": did_document}
    )
    updated_did_doc = did_update_result.get("didDocument")
    updated_did = did_update_result.get("did")

    assert updated_did == did, "DID mismatch after update."
    assert (
        "service" in updated_did_doc
    ), "Key 'service' is missing in updated DID document."
    assert (
        updated_did_doc["service"] == service
    ), "Service does not match the expected value!"

    print(f"Updated DID Document: {format_json(updated_did_doc)}")
    return updated_did_doc


async def deactivate_did(issuer, did):
    """Deactivate a DID on the Cheqd testnet."""
    did_deactivate_result = await issuer.post(
        "/did/cheqd/deactivate",
        json={
            "did": did,
            "options": {"network": "testnet"},
        },
    )

    assert did_deactivate_result.get("did") == did, "DID mismatch after deactivation."
    assert (
        did_deactivate_result.get("did_document_metadata", {}).get("deactivated") is True
    ), "DID document metadata does not contain deactivated=true."

    print(f"Deactivated DID: {format_json(did_deactivate_result) }")


async def create_schema(issuer, did):
    """Create a schema on the Cheqd testnet."""
    schema_create_result = await issuer.post(
        "/anoncreds/schema",
        json={
            "schema": {
                "attrNames": ["score"],
                "issuerId": did,
                "name": "Example schema",
                "version": "1.0",
            }
        },
    )
    print(f"Created schema: {format_json(schema_create_result)}")
    schema_state = schema_create_result.get("schema_state")
    assert schema_state.get("state") == "finished", "Schema state is not finished."
    assert "schema_id" in schema_state, "Key 'schema_id' is missing in schema_state."

    schema_id = schema_state.get("schema_id")
    assert (
        did in schema_id
    ), f"schema_id does not contain the expected DID. Expected '{did}' in '{schema_id}'."

    return schema_id


async def create_credential_definition(issuer, did, schema_id):
    """Create a credential definition on the connected datastore."""
    cred_def_create_result = await issuer.post(
        "/anoncreds/credential-definition",
        json={
            "credential_definition": {
                "issuerId": did,
                "schemaId": schema_id,
                "tag": "default",
            }
        },
    )

    cred_def_state = cred_def_create_result.get("credential_definition_state", {})
    assert cred_def_state.get("state") == "finished", "Cred def state is not finished."
    assert (
        "credential_definition_id" in cred_def_state
    ), "Key 'credential_definition_id' is missing in credential_definition_state."

    credential_definition_id = cred_def_state.get("credential_definition_id")
    assert (
        did in credential_definition_id
    ), "credential_definition_id does not contain the expected DID."

    print(f"Created credential definition: {format_json(cred_def_create_result)}")
    return credential_definition_id


async def assert_credential_definitions(issuer, credential_definition_id):
    """Retrieve all cred_defs & ensure array contain created credential_definition_id."""
    get_result = await issuer.get("/anoncreds/credential-definitions")

    credential_definition_ids = get_result.get("credential_definition_ids", [])
    assert (
        credential_definition_id in credential_definition_ids
    ), "credential_definition_ids does not contain the expected credential_definition_id."


async def assert_wallet_dids(issuer, did):
    """Retrieve all wallet dids and ensure array contain created did."""
    get_result = await issuer.get("/wallet/did?method=cheqd")

    dids = get_result.get("results", [])
    assert any(obj.get("did") == did for obj in dids), f"DID {did} not found in array"


async def issue_credential_v2(
    issuer: Controller,
    holder: Controller,
    issuer_connection_id: str,
    holder_connection_id: str,
    cred_def_id: str,
    attributes: Mapping[str, str],
) -> Tuple[V20CredExRecordDetail, V20CredExRecordDetail]:
    """Issue an credential using issue-credential/2.0.

    Issuer and holder should already be connected.
    """

    issuer_cred_ex = await issuer.post(
        "/issue-credential-2.0/send",
        json={
            "auto_issue": True,
            "auto_remove": False,
            "comment": "Credential from minimal example",
            "trace": False,
            "connection_id": issuer_connection_id,
            "filter": {
                "anoncreds": {
                    "cred_def_id": cred_def_id,
                }
            },
            "credential_preview": {
                "type": "issue-credential-2.0/2.0/credential-preview",  # pyright: ignore
                "attributes": [
                    {
                        "name": name,
                        "value": value,
                    }
                    for name, value in attributes.items()
                ],
            },
        },
        response=V20CredExRecord,
    )
    issuer_cred_ex_id = issuer_cred_ex.cred_ex_id

    holder_cred_ex = await holder.event_with_values(
        topic="issue_credential_v2_0",
        event_type=V20CredExRecord,
        connection_id=holder_connection_id,
        state="offer-received",
    )
    holder_cred_ex_id = holder_cred_ex.cred_ex_id

    await holder.post(
        f"/issue-credential-2.0/records/{holder_cred_ex_id}/send-request",
        response=V20CredExRecord,
    )

    await issuer.event_with_values(
        topic="issue_credential_v2_0",
        cred_ex_id=issuer_cred_ex_id,
        state="request-received",
    )

    await holder.event_with_values(
        topic="issue_credential_v2_0",
        cred_ex_id=holder_cred_ex_id,
        state="credential-received",
    )

    await holder.post(
        f"/issue-credential-2.0/records/{holder_cred_ex_id}/store",
        json={},
        response=V20CredExRecordDetail,
    )

    issuer_cred_ex = await issuer.event_with_values(
        topic="issue_credential_v2_0",
        event_type=V20CredExRecord,
        cred_ex_id=issuer_cred_ex_id,
        state="done",
    )

    holder_cred_ex = await holder.event_with_values(
        topic="issue_credential_v2_0",
        event_type=V20CredExRecord,
        cred_ex_id=holder_cred_ex_id,
        state="done",
    )

    return (
        V20CredExRecordDetail(cred_ex_record=issuer_cred_ex),
        V20CredExRecordDetail(cred_ex_record=holder_cred_ex),
    )
