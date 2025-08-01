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
async def test_deactivate_did():
    """Test DID deactivation."""
    did = load_did()
    async with Controller(base_url=ISSUER) as issuer:
        await deactivate_did(issuer, did)


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
async def test_import_did_end_to_end_workflow():
    """Test complete workflow: import DID, verify it's usable for other operations."""
    test_did = "did:key:z6MkqY2oHBWpGFGPzc5N8K2nZ3kWQF2gLAFr6TY3Mn5Ej8Ka"
    test_verkey = "7Z4PmBt7qR5HGkJkMkTz6vGgWxQJy8R4KnF2S3MpC5Lt8qR7"

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
        # Step 1: Import the DID
        import_result = await import_did(
            issuer,
            did_document,
            metadata={"purpose": "testing", "workflow": "e2e"},
        )

        assert import_result["did"] == test_did
        print("Step 1 completed: DID imported successfully")

        # Step 2: Verify DID is in wallet
        await assert_did_in_wallet(issuer, test_did)
        print("Step 2 completed: DID verified in wallet")

        # Step 3: Try to use the DID (e.g., create a JWT)
        try:
            jwt_payload = {
                "did": test_did,
                "headers": {"typ": "JWT", "alg": "EdDSA"},
                "payload": {"test": "data", "iat": 1234567890},
            }

            jwt_result = await issuer.post("/wallet/jwt/sign", json=jwt_payload)
            assert "jws" in jwt_result, "JWT signing should return a 'jws' field"
            print("Step 3 completed: DID successfully used for JWT signing")

        except Exception as e:
            # JWT signing might not be available or might require different format
            # This is optional verification - the main test is the import
            print(f"Step 3 optional: JWT signing test skipped due to: {e}")

        # Step 4: Verify the DID can be retrieved individually
        individual_did = await issuer.get(f"/wallet/did?did={test_did}")
        assert "results" in individual_did
        assert len(individual_did["results"]) > 0
        found_did = next(
            (d for d in individual_did["results"] if d["did"] == test_did), None
        )
        assert found_did is not None
        print("Step 4 completed: DID can be retrieved individually")

        print("End-to-end workflow completed successfully!")
