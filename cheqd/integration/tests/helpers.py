import json
import os
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Tuple, Type
from urllib.parse import quote
from uuid import uuid4

from acapy_controller import Controller
from acapy_controller.controller import Minimal, MinType
from acapy_controller.models import V20PresExRecord
from typing_extensions import Union

DID_CACHE_FILE = "did_cache.json"
SCHEMA_CACHE_FILE = "schema_cache.json"


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


@dataclass
class CredInfo(Minimal):
    """Credential information."""

    referent: str
    attrs: Dict[str, Any]


@dataclass
class CredPrecis(Minimal):
    """Credential precis."""

    cred_info: CredInfo
    presentation_referents: List[str]

    @classmethod
    def deserialize(cls: Type[MinType], value: Mapping[str, Any]) -> MinType:
        """Deserialize the credential precis."""
        value = dict(value)
        if cred_info := value.get("cred_info"):
            value["cred_info"] = CredInfo.deserialize(cred_info)
        return super().deserialize(value)


@dataclass
class ProofRequest(Minimal):
    """Proof request."""

    requested_attributes: Dict[str, Any]
    requested_predicates: Dict[str, Any]


@dataclass
class PresSpec(Minimal):
    """Presentation specification."""

    requested_attributes: Dict[str, Any]
    requested_predicates: Dict[str, Any]
    self_attested_attributes: Dict[str, Any]


@dataclass
class Settings(Minimal):
    """Settings information."""


def save_did(did):
    """Save the given DID to a JSON file."""
    with open(DID_CACHE_FILE, "w") as f:
        json.dump({"did": did}, f)


def load_did():
    """Load the DID from a JSON file if it exists."""
    if os.path.exists(DID_CACHE_FILE):
        with open(DID_CACHE_FILE, "r") as f:
            try:
                data = json.load(f)
                return data.get("did")
            except json.JSONDecodeError:
                return None
    return None


def save_schema(schema_id):
    """Save the given Schema ID to a JSON file."""
    with open(SCHEMA_CACHE_FILE, "w") as f:
        json.dump({"schema_id": schema_id}, f)


def load_schema():
    """Load the Schema from a JSON file if it exists."""
    if os.path.exists(SCHEMA_CACHE_FILE):
        with open(SCHEMA_CACHE_FILE, "r") as f:
            try:
                data = json.load(f)
                return data.get("schema_id")
            except json.JSONDecodeError:
                return None
    return None


def remove_cache():
    """Remove the cache files."""
    if os.path.exists(DID_CACHE_FILE):
        os.remove(DID_CACHE_FILE)
    if os.path.exists(SCHEMA_CACHE_FILE):
        os.remove(SCHEMA_CACHE_FILE)


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
    assert "service" in updated_did_doc, (
        "Key 'service' is missing in updated DID document."
    )
    assert updated_did_doc["service"] == service, (
        "Service does not match the expected value!"
    )

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
        did_deactivate_result.get("didDocumentMetadata", {}).get("deactivated") is True
    ), "DID document metadata does not contain deactivated=true."

    print(f"Deactivated DID: {format_json(did_deactivate_result)}")
    remove_cache()


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
    assert did in schema_id, (
        f"schema_id does not contain the expected DID. Expected '{did}' in '{schema_id}'."
    )

    return schema_id


async def update_schema(issuer, did):
    """Update a schema on the Cheqd testnet."""
    schema_create_result = await issuer.post(
        "/anoncreds/schema",
        json={
            "schema": {
                "attrNames": ["score", "name"],
                "issuerId": did,
                "name": "Example schema",
                "version": "2.0",
            }
        },
    )
    print(f"Created schema: {format_json(schema_create_result)}")
    schema_state = schema_create_result.get("schema_state")
    assert schema_state.get("state") == "finished", "Schema state is not finished."
    assert "schema_id" in schema_state, "Key 'schema_id' is missing in schema_state."

    schema_id = schema_state.get("schema_id")
    assert did in schema_id, (
        f"schema_id does not contain the expected DID. Expected '{did}' in '{schema_id}'."
    )

    return schema_id


async def create_credential_definition(
    issuer,
    did: str,
    schema_id: str,
    support_revocation: bool = False,
    tag: str = "default",
):
    """Create a credential definition on the connected datastore."""
    cred_def_create_result = await issuer.post(
        "/anoncreds/credential-definition",
        json={
            "credential_definition": {
                "issuerId": did,
                "schemaId": schema_id,
                "tag": tag,
            },
            "options": {"support_revocation": support_revocation},
        },
    )

    cred_def_state = cred_def_create_result.get("credential_definition_state", {})
    assert cred_def_state.get("state") == "finished", "Cred def state is not finished."
    assert "credential_definition_id" in cred_def_state, (
        "Key 'credential_definition_id' is missing in credential_definition_state."
    )

    credential_definition_id = cred_def_state.get("credential_definition_id")
    assert did in credential_definition_id, (
        "credential_definition_id does not contain the expected DID."
    )

    return credential_definition_id


async def assert_credential_definitions(issuer, credential_definition_id):
    """Retrieve all cred_defs & ensure array contain created credential_definition_id."""
    get_result = await issuer.get("/anoncreds/credential-definitions")

    credential_definition_ids = get_result.get("credential_definition_ids", [])
    assert credential_definition_id in credential_definition_ids, (
        "credential_definition_ids does not contain the expected credential_definition_id."
    )


async def assert_active_revocation_registry(issuer, credential_definition_id):
    """cred_defs with revocation support should contain at least one active registry."""
    encoded_id = quote(credential_definition_id, safe="")
    get_result = await issuer.get(f"/anoncreds/revocation/active-registry/{encoded_id}")

    assert get_result, "no active revocation registry for the credential_definition_id."


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
        "/issue-credential-2.0/send-offer",
        json={
            "auto_issue": False,
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

    await issuer.post(
        f"/issue-credential-2.0/records/{issuer_cred_ex_id}/issue",
        json={},
        response=V20CredExRecordDetail,
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
    issuer_anon_record = await issuer.event_with_values(
        topic="issue_credential_v2_0_anoncreds",
    )

    holder_cred_ex = await holder.event_with_values(
        topic="issue_credential_v2_0",
        event_type=V20CredExRecord,
        cred_ex_id=holder_cred_ex_id,
        state="done",
    )
    holder_anon_record = await holder.event_with_values(
        topic="issue_credential_v2_0_anoncreds",
    )

    return (
        V20CredExRecordDetail(cred_ex_record=issuer_cred_ex, details=issuer_anon_record),
        V20CredExRecordDetail(cred_ex_record=holder_cred_ex, details=holder_anon_record),
    )


def auto_select_credentials_for_presentation_request(
    presentation_request: Union[ProofRequest, dict],
    relevant_creds: List[CredPrecis],
) -> PresSpec:
    """Select credentials to use for presentation automatically."""
    if isinstance(presentation_request, dict):
        presentation_request = ProofRequest.deserialize(presentation_request)

    requested_attributes = {}
    for pres_referrent in presentation_request.requested_attributes.keys():
        for cred_precis in relevant_creds:
            if pres_referrent in cred_precis.presentation_referents:
                requested_attributes[pres_referrent] = {
                    "cred_id": cred_precis.cred_info.referent,
                    "revealed": True,
                }
    requested_predicates = {}
    for pres_referrent in presentation_request.requested_predicates.keys():
        for cred_precis in relevant_creds:
            if pres_referrent in cred_precis.presentation_referents:
                requested_predicates[pres_referrent] = {
                    "cred_id": cred_precis.cred_info.referent,
                    "timestamp": int(time.time()),
                }

    return PresSpec.deserialize(
        {
            "requested_attributes": requested_attributes,
            "requested_predicates": requested_predicates,
            "self_attested_attributes": {},
        }
    )


async def present_proof_v2(
    holder: Controller,
    verifier: Controller,
    holder_connection_id: str,
    verifier_connection_id: str,
    *,
    name: Optional[str] = None,
    version: Optional[str] = None,
    comment: Optional[str] = None,
    requested_attributes: Optional[List[Mapping[str, Any]]] = None,
    requested_predicates: Optional[List[Mapping[str, Any]]] = None,
    non_revoked: Optional[Mapping[str, int]] = None,
):
    """Present a credential using present proof v2."""

    is_verifier_anoncreds = (await verifier.get("/settings", response=Settings)).get(
        "wallet.type"
    ) == "askar-anoncreds"

    attrs = {
        "name": name or "proof",
        "version": version or "0.1.0",
        "requested_attributes": {
            str(uuid4()): attr for attr in requested_attributes or []
        },
        "requested_predicates": {
            str(uuid4()): pred for pred in requested_predicates or []
        },
        "non_revoked": (non_revoked if non_revoked else None),
    }

    if is_verifier_anoncreds:
        presentation_request = {
            "anoncreds": attrs,
        }
    else:
        presentation_request = {
            "indy": attrs,
        }
    verifier_pres_ex = await verifier.post(
        "/present-proof-2.0/send-request",
        json={
            "auto_verify": False,
            "auto_remove": False,
            "comment": comment or "Presentation request from minimal",
            "connection_id": verifier_connection_id,
            "presentation_request": presentation_request,
            "trace": False,
        },
        response=V20PresExRecord,
    )
    verifier_pres_ex_id = verifier_pres_ex.pres_ex_id

    holder_pres_ex = await holder.event_with_values(
        topic="present_proof_v2_0",
        event_type=V20PresExRecord,
        connection_id=holder_connection_id,
        state="request-received",
    )
    assert holder_pres_ex.pres_request
    holder_pres_ex_id = holder_pres_ex.pres_ex_id

    relevant_creds = await holder.get(
        f"/present-proof-2.0/records/{holder_pres_ex_id}/credentials",
        response=List[CredPrecis],
    )
    assert holder_pres_ex.by_format.pres_request
    proof_request = holder_pres_ex.by_format.pres_request.get(
        "anoncreds"
    ) or holder_pres_ex.by_format.pres_request.get("indy")
    pres_spec = auto_select_credentials_for_presentation_request(
        proof_request, relevant_creds
    )
    if is_verifier_anoncreds:
        proof = {"anoncreds": pres_spec.serialize()}
    else:
        proof = {"indy": pres_spec.serialize()}

    print(proof)

    presentation = await holder.post(
        f"/present-proof-2.0/records/{holder_pres_ex_id}/send-presentation",
        json=proof,
        response=V20PresExRecord,
    )
    print(presentation)
    assert presentation.state == "presentation-sent"

    await verifier.event_with_values(
        topic="present_proof_v2_0",
        event_type=V20PresExRecord,
        pres_ex_id=verifier_pres_ex_id,
        state="presentation-received",
    )

    await verifier.post(
        f"/present-proof-2.0/records/{verifier_pres_ex_id}/verify-presentation",
        json={},
        response=V20PresExRecord,
    )
    verifier_pres_ex = await verifier.event_with_values(
        topic="present_proof_v2_0",
        event_type=V20PresExRecord,
        pres_ex_id=verifier_pres_ex_id,
        state="done",
    )

    holder_pres_ex = await holder.event_with_values(
        topic="present_proof_v2_0",
        event_type=V20PresExRecord,
        pres_ex_id=holder_pres_ex_id,
        state="done",
    )

    return holder_pres_ex, verifier_pres_ex
