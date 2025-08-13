import asyncio
import time
from os import getenv

import pytest
import pytest_asyncio
from acapy_controller import Controller
from acapy_controller.protocols import didexchange

from .helpers import (
    assert_active_revocation_registry,
    assert_credential_definitions,
    assert_did_in_wallet,
    assert_wallet_dids,
    create_credential_definition,
    create_did,
    create_schema,
    deactivate_did,
    import_did,
    issue_credential_v2,
    load_did,
    load_schema,
    present_proof_v2,
    resolve_did,
    save_did,
    save_schema,
    update_did,
    update_schema,
)

ISSUER = getenv("ISSUER", "http://issuer:3001")
HOLDER = getenv("HOLDER", "http://holder:4001")


@pytest_asyncio.fixture(scope="session")
async def shared_did():
    """Fixture to create DID and store for reuse with tests."""
    issuer = Controller(base_url=ISSUER)
    did = load_did()
    if not did:
        did = await create_did(issuer)
        save_did(did)
    return did


@pytest_asyncio.fixture(scope="session")
async def shared_schema():
    """Fixture to create Schema and store for reuse with tests."""
    issuer = Controller(base_url=ISSUER)
    did = load_did()
    schema_id = load_schema()
    if not schema_id:
        schema_id = await create_schema(issuer, did)
        save_schema(schema_id)
    return schema_id


@pytest.mark.asyncio
async def test_create_and_resolve_did(shared_did):
    """Test DID creation and resolution."""
    did = shared_did
    async with Controller(base_url=ISSUER) as issuer:
        assert did.startswith("did:")
        await resolve_did(issuer, did)


@pytest.mark.asyncio
async def test_update_did():
    """Test DID update."""
    did = load_did()
    async with Controller(base_url=ISSUER) as issuer:
        did_doc = await resolve_did(issuer, did)
        await update_did(issuer, did, did_doc)


@pytest.mark.asyncio
async def test_create_schema_and_credential_definition(shared_schema):
    """Test schema and credential definition creation."""
    did = load_did()
    schema_id = shared_schema

    if not schema_id:
        assert False, "Schema creation failed"

    async with Controller(base_url=ISSUER) as issuer:
        credential_definition_id = await create_credential_definition(
            issuer, did, schema_id
        )

        await assert_credential_definitions(issuer, credential_definition_id)
        await assert_wallet_dids(issuer, did)
        assert credential_definition_id is not None


@pytest.mark.asyncio
async def test_update_schema():
    """Test Update Schema."""
    did = load_did()

    async with Controller(base_url=ISSUER) as issuer:
        await update_schema(issuer, did)


@pytest.mark.asyncio
async def test_create_credential_definition_with_revocation():
    """Test schema and credential definition with revocation."""
    did = load_did()
    schema_id = load_schema()
    async with Controller(base_url=ISSUER) as issuer:
        credential_definition_id = await create_credential_definition(
            issuer, did, schema_id, True, "revocable1"
        )

        await assert_credential_definitions(issuer, credential_definition_id)
        await assert_wallet_dids(issuer, did)
        assert credential_definition_id is not None
        # assert active revocation registry for credential_definition_id
        await assert_active_revocation_registry(issuer, credential_definition_id)


@pytest.mark.asyncio
async def test_issue_credential():
    """Test credential issuance."""
    did = load_did()
    schema_id = load_schema()
    async with (
        Controller(base_url=ISSUER) as issuer,
        Controller(base_url=HOLDER) as holder,
    ):
        credential_definition_id = await create_credential_definition(
            issuer, did, schema_id, False, "default2"
        )

        # Connect issuer and holder
        issuer_conn_with_anoncreds_holder, holder_anoncreds_conn = await didexchange(
            issuer, holder
        )

        issue_credential_result = await issue_credential_v2(
            issuer,
            holder,
            issuer_conn_with_anoncreds_holder.connection_id,
            holder_anoncreds_conn.connection_id,
            credential_definition_id,
            {"score": "99"},
        )
        assert issue_credential_result is not None

        _, verifier_pres_ex = await present_proof_v2(
            holder=holder,
            verifier=issuer,
            holder_connection_id=holder_anoncreds_conn.connection_id,
            verifier_connection_id=issuer_conn_with_anoncreds_holder.connection_id,
            requested_attributes=[
                {
                    "name": "score",
                    "restrictions": [{"cred_def_id": credential_definition_id}],
                }
            ],
        )
        assert verifier_pres_ex.verified


@pytest.mark.asyncio
async def test_issue_credential_with_revocation():
    """Test credential issuance with revocation."""
    did = load_did()
    schema_id = load_schema()
    async with (
        Controller(base_url=ISSUER) as issuer,
        Controller(base_url=HOLDER) as holder,
    ):
        # create credential definition with revocation
        credential_definition_id = await create_credential_definition(
            issuer, did, schema_id, True, "revocable2"
        )

        # Connect issuer and holder
        issuer_conn_with_anoncreds_holder, holder_anoncreds_conn = await didexchange(
            issuer, holder
        )

        issuer_cred_ex, _ = await issue_credential_v2(
            issuer,
            holder,
            issuer_conn_with_anoncreds_holder.connection_id,
            holder_anoncreds_conn.connection_id,
            credential_definition_id,
            {"score": "99"},
        )
        assert issuer_cred_ex is not None

        # Verify credential
        _, verifier_pres_ex = await present_proof_v2(
            holder=holder,
            verifier=issuer,
            holder_connection_id=holder_anoncreds_conn.connection_id,
            verifier_connection_id=issuer_conn_with_anoncreds_holder.connection_id,
            requested_predicates=[
                {
                    "name": "score",
                    "p_value": 50,
                    "p_type": ">",
                    "restrictions": [{"cred_def_id": credential_definition_id}],
                }
            ],
            non_revoked={"to": int(time.time()) + 300},
        )
        assert verifier_pres_ex.verified == "true", "Presentation is not verified"

        # Revoke credential
        await issuer.post(
            url="/anoncreds/revocation/revoke",
            json={
                "rev_reg_id": issuer_cred_ex.details["rev_reg_id"],
                "cred_rev_id": issuer_cred_ex.details["cred_rev_id"],
                "publish": True,
            },
        )

        # Verify credential
        _, verifier_pres_ex = await present_proof_v2(
            holder=holder,
            verifier=issuer,
            holder_connection_id=holder_anoncreds_conn.connection_id,
            verifier_connection_id=issuer_conn_with_anoncreds_holder.connection_id,
            requested_predicates=[
                {
                    "name": "score",
                    "p_value": 50,
                    "p_type": ">",
                    "restrictions": [{"cred_def_id": credential_definition_id}],
                }
            ],
            non_revoked={"to": int(time.time())},
        )
        assert verifier_pres_ex.verified == "false", "Presentation shouldn't be verified"


@pytest.mark.asyncio
async def test_import_did_key_method():
    """Test importing a did:key DID into the wallet."""
    # Test data - a valid did:key DID document
    test_did = "did:key:z6MkhaXgBZDvotDkL5257faizNL939X6C56mZVQXgfYjeJKC"
    test_verkey = "8HH5gYEeNc3z7PYXmd54d4x6qAfCNrqQqEB3nS7Zfu7K"
    test_metadata = {"imported": True, "source": "external_system"}
    did_document = {
        "id": test_did,
        "verificationMethod": [
            {
                "id": f"{test_did}#key-1",
                "type": "Ed25519VerificationKey2018",
                "controller": test_did,
                "publicKeyBase58": test_verkey,
            }
        ],
        "authentication": [f"{test_did}#key-1"],
        "assertionMethod": [f"{test_did}#key-1"],
    }
    async with Controller(base_url=ISSUER) as issuer:
        # Import the DID
        import_result = await import_did(issuer, did_document, metadata=test_metadata)

        # Verify the import result
        assert import_result["did"] == test_did
        assert import_result["verkey"] == test_verkey
        assert import_result["method"] == "key"
        assert import_result["key_type"] == "ed25519"
        assert import_result["metadata"]["imported"]
        assert import_result["metadata"]["source"] == "external_system"
        # Verify the DID is now in the wallet
        await assert_did_in_wallet(issuer, test_did)


@pytest.mark.asyncio
async def test_import_did_web_method():
    """Test importing a did:web DID into the wallet."""
    test_did = "did:web:example.com:user:holder"

    did_document = {
        "id": test_did,
        "verificationMethod": [
            {
                "id": f"{test_did}#key-1",
                "type": "Ed25519VerificationKey2020",
                "controller": test_did,
                "publicKeyMultibase": "z6MkhaXgBZDvotDkL5257faizNL939X6C56mZVQXgfYjeJKC",
            }
        ],
        "authentication": [f"{test_did}#key-1"],
    }

    async with Controller(base_url=HOLDER) as holder:
        # Import the DID (without private key for read-only DID)
        import_result = await import_did(holder, did_document)

        # Verify the import result
        assert import_result["did"] == test_did
        assert import_result["method"] == "web"

        # Verify the DID is now in the wallet
        await assert_did_in_wallet(holder, test_did)


@pytest.mark.asyncio
async def test_cheqd_did_end_to_end_workflow():
    """Test complete workflow for did:cheqd: import, verify, use."""
    # Define test DID attributes
    cheqd_did = "did:cheqd:testnet:c8b04ae0-9bff-4e94-b401-f2997b9caa5e"
    test_seed = "9fjK2pXE7qBVzRhWmtQAN1yUvLGe0cIL"

    async with Controller(base_url=ISSUER) as issuer:
        # Step 1: Create the key in wallet using the seed
        key_response = await issuer.post(
            "/wallet/keys",
            json={
                "seed": test_seed,
                "kid": f"{cheqd_did}#key-1",
                "alg": "ed25519",
            },
        )

        cheqd_did_document = {
            "id": cheqd_did,
            "controller": [cheqd_did],
            "verificationMethod": [
                {
                    "id": f"{cheqd_did}#key-1",
                    "type": "Ed25519VerificationKey2018",
                    "controller": cheqd_did,
                    "publicKeyMultibase": key_response["multikey"],
                }
            ],
            "authentication": [f"{cheqd_did}#key-1"],
            "assertionMethod": [f"{cheqd_did}#key-1"],
        }
        # Step 2: Import the DID document to the wallet
        import_result = await import_did(
            issuer,
            cheqd_did_document,
            metadata={"purpose": "testing", "did_type": "cheqd"},
        )

        assert import_result["did"] == cheqd_did
        print("Step 1 completed: cheqd DID imported successfully")

        # Step 3: Verify DID is in wallet or state store
        await assert_did_in_wallet(issuer, cheqd_did)
        print("Step 2 completed: cheqd DID verified in wallet")

        # Step 4: Attempt to use the DID for signing (JWT or VC)
        jwt_payload = {
            "did": cheqd_did,
            "headers": {"typ": "JWT", "alg": "EdDSA"},
            "payload": {"test": "cheqd", "iat": 1234567890},
        }

        jwt_result = await issuer.post("/wallet/jwt/sign", json=jwt_payload)

        payload = {"jwt": jwt_result}
        jwt_verify = await issuer.post("/wallet/jwt/verify", json=payload)
        assert "valid" in jwt_verify, "JWT verification should return 'valid' field"
        assert jwt_verify["valid"] is True, "JWT should be valid"
        assert jwt_verify["payload"]["test"] == "cheqd", "JWT payload should match"
        assert jwt_verify["payload"]["iat"] == 1234567890, "JWT payload should match"
        print("Step 3 completed: JWT signing using cheqd DID successful")

        # Step 5: Retrieve the DID individually
        individual_did = await issuer.get(f"/wallet/did?did={cheqd_did}")
        assert "results" in individual_did
        assert len(individual_did["results"]) > 0
        found_did = next(
            (d for d in individual_did["results"] if d["did"] == cheqd_did), None
        )
        assert found_did is not None
        print("Step 4 completed: cheqd DID successfully retrieved individually")

        print("End-to-end workflow for did:cheqd completed successfully!")


@pytest.mark.asyncio
async def test_didexchange_with_cheqd_public_did():
    """Test didexchange with cheqd public DID."""
    issuer_did = "did:cheqd:testnet:c8b04ae0-9bff-4e94-b401-f2997b9caa5e"
    async with (
        Controller(base_url=ISSUER) as issuer,
        Controller(base_url=HOLDER) as holder,
    ):
        # Set fixed did as public DID for issuer
        public_did_response = await issuer.post(f"/wallet/did/public?did={issuer_did}")
        assert public_did_response["result"]["did"] == issuer_did, (
            "Public DID should match issuer DID"
        )
        print(f"Cheqd DID {issuer_did} has been set as public DID")

        # Holder create connection invitation using the public cheqd DID
        invitation_response = await holder.post(
            f"/didexchange/create-request?their_public_did={issuer_did}&alias=Holder-to-Issuer&auto_accept=true&my_endpoint=http%3A%2F%2Fholder%3A4002&my_label=Holder-using-public-did"
        )
        connection_id_holder = invitation_response["connection_id"]
        # Verify invitation contains the cheqd DID
        assert invitation_response.get("state") == "request", (
            "Invitation should be in 'request' state"
        )
        assert invitation_response.get("their_public_did") == issuer_did, (
            "Invitation should contain the cheqd public DID"
        )
        assert invitation_response.get("alias") == "Holder-to-Issuer", (
            "Invitation alias should match"
        )
        await asyncio.sleep(3)
        # Issuer checks for incoming connection request
        connections = await issuer.get(
            "/connections?descending=false&limit=100&offset=0&order_by=id&state=request"
        )
        assert len(connections["results"]) > 0, "No connection requests found"
        connection_id_issuer = connections["results"][0]["connection_id"]
        # Issuer accepts invitation
        receive_response = await issuer.post(
            f"/didexchange/{connection_id_issuer}/accept-request?my_endpoint=http%3A%2F%2Fissuer%3A3002&use_public_did=false"
        )
        assert receive_response["state"] == "response", (
            "Connection should be response after accepting request"
        )
        await asyncio.sleep(3)
        # Issuer checks connection status
        issuer_connection = await issuer.get(f"/connections/{connection_id_issuer}")
        assert issuer_connection["state"] == "active", (
            "Issuer connection should be active after accepting request"
        )
        assert issuer_connection["connection_protocol"] == "didexchange/1.0", (
            "Connection protocol should be didexchange/1.0"
        )
        assert issuer_connection["rfc23_state"] == "completed", (
            "Connection should be in completed state"
        )
        assert issuer_connection["their_label"] == "Holder-using-public-did", (
            "Connection label should match holder's label"
        )

        holder_connection = await holder.get(f"/connections/{connection_id_holder}")
        assert holder_connection["state"] == "active", (
            "Holder connection should be active after accepting the request"
        )
        print("DID Exchange completed successfully")


@pytest.mark.asyncio
async def test_oob_invitation_with_cheqd_did():
    """Test out-of-band invitation with cheqd DID."""
    issuer_did = "did:cheqd:testnet:c8b04ae0-9bff-4e94-b401-f2997b9caa5e"
    async with (
        Controller(base_url=ISSUER) as issuer,
        Controller(base_url=HOLDER) as holder,
    ):
        # Create out-of-band invitation with cheqd public DID
        oob_invitation_response = await issuer.post(
            "/out-of-band/create-invitation?auto_accept=true&create_unique_did=false&multi_use=false",
            json={
                "alias": "Issuer to Holder Connection",
                "use_public_did": True,
                "my_label": "Issuer with Cheqd Public DID",
                "handshake_protocols": ["https://didcomm.org/didexchange/1.0"],
            },
        )
        assert oob_invitation_response["state"] == "initial", (
            "OOB invitation should be in 'initial' state"
        )
        assert oob_invitation_response["invitation"] is not None, (
            "OOB invitation should contain an invitation object"
        )
        assert oob_invitation_response["invitation_url"] is not None, (
            "OOB invitation should contain an invitation URL"
        )
        oob_invitation = oob_invitation_response["invitation"]
        assert "services" in oob_invitation or "service" in oob_invitation

        # Holder receives OOB invitation
        receive_oob_response = await holder.post(
            "/out-of-band/receive-invitation?alias=IssuerConnection&auto_accept=true&use_existing_connection=false",
            json=oob_invitation,
        )
        assert receive_oob_response["role"] == "receiver", (
            "OOB invitation should be received as a receiver"
        )
        assert receive_oob_response["state"] == "deleted", (
            "OOB invitation should be in 'deleted' state after receiving"
        )
        holder_oob_conn_id = receive_oob_response["connection_id"]
        await asyncio.sleep(3)
        holder_connection = await holder.get(f"/connections/{holder_oob_conn_id}")
        assert holder_connection["state"] == "active", (
            "Holder connection should be active after accepting the request"
        )
        assert holder_connection["their_public_did"] == issuer_did, (
            "Holder connection should have the issuer's public DID"
        )
        assert holder_connection["alias"] == "IssuerConnection", (
            "Holder connection alias should match the OOB invitation alias"
        )
        assert holder_connection["their_label"] == "Issuer with Cheqd Public DID", (
            "Holder connection label should match the issuer's label"
        )

        print("OOB Invitation created successfully with cheqd DID")


@pytest.mark.asyncio
async def test_deactivate_did():
    """Test DID deactivation."""
    did = load_did()
    async with Controller(base_url=ISSUER) as issuer:
        await deactivate_did(issuer, did)
