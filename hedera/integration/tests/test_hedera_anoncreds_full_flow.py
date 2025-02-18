import logging
import time

LOGGER = logging.getLogger(__name__)


class TestHederaAnonCredsFullFlow:
    """Aggregate operation flows."""

    def test_flow(self, issuer, holder, Something):
        """Test full flow of credential issuance and revocation."""
        print("""
              ###########################################
              #       Create multi-tenant wallets       #
              ###########################################
              """)
        print("""
              +-----------------------------------------+
              |       Holder creates wallet             |
              +-----------------------------------------+
              """)
        holder.create_wallet(persist_token=True)

        print("""
              +-----------------------------------------+
              |       Issuer creates wallet             |
              +-----------------------------------------+
              """)
        issuer.create_wallet(persist_token=True)

        print("""
              ###########################################
              #  Connection between issuer & holder     #
              ###########################################
              """)
        print("""
              +-----------------------------------------+
              |  Issuer creates connection invitation   |
              +-----------------------------------------+
              """)
        resp = issuer.create_invitation(
            alias="Holder",
            goal="To issue a test credential",
            label="Invitation to Holder",
        )

        invitation = resp.get("invitation")
        assert invitation

        time.sleep(10)

        print("""
              +-----------------------------------------+
              |  Holder accepts connection invitation   |
              +-----------------------------------------+
              """)
        holder.receive_invitation(invitation)

        time.sleep(10)

        print("""
              +-----------------------------------------+
              |  Issuer validates connection created    |
              +-----------------------------------------+
              """)
        resp = issuer.list_connections()

        issuer_connections_results = resp.get("results")
        assert issuer_connections_results
        assert type(issuer_connections_results) is list
        assert len(issuer_connections_results) == 1

        [single_connection] = issuer_connections_results
        assert single_connection.get("alias") == "Holder"
        assert single_connection.get("state") == "active"

        issuer_connection_id = single_connection.get("connection_id")
        assert issuer_connection_id

        print("""
              ###########################################
              #          Issuer credential setup        #
              ###########################################
              """)
        print("""
              +----------------------------------------+
              |  Issuer registers DID through Hedera   |
              +----------------------------------------+
              """)
        key_type = "ed25519"
        key_type_capitalized = key_type.capitalize()

        resp = issuer.register_did(key_type=key_type_capitalized)

        assert resp.get("key_type") == key_type

        issuer_did = resp.get("did")
        assert issuer_did

        print("""
              +-----------------------------------------+
              |        Issuer registers schema          |
              +-----------------------------------------+
              """)
        schema_name = "Example schema"
        schema_attribute_names = ["name", "age"]
        schema_version = "1.0"

        resp = issuer.register_schema(
            name=schema_name,
            version=schema_version,
            issuer_id=issuer_did,
            attribute_names=schema_attribute_names,
        )

        schema_state = resp.get("schema_state")
        assert schema_state

        schema_id = schema_state.get("schema_id")
        assert schema_id

        time.sleep(10)

        print("""
              +---------------------------------------------+
              |  Issuer registers credential definition     |
              +---------------------------------------------+
              """)
        credential_definition_tag = "default"

        resp = issuer.register_credential_definition(
            schema_id=schema_id, issuer_id=issuer_did, tag=credential_definition_tag
        )

        credential_definition_state = resp.get("credential_definition_state")
        assert credential_definition_state

        assert credential_definition_state.get("state") == "finished"

        credential_definition = credential_definition_state.get("credential_definition")

        assert credential_definition.get("schemaId") == schema_id
        assert credential_definition.get("issuerId") == issuer_did
        assert credential_definition.get("tag") == credential_definition_tag
        assert credential_definition.get("type") == "CL"
        assert credential_definition.get("value")
        assert credential_definition.get("value").get("primary") == {
            "n": Something,
            "r": Something,
            "rctxt": Something,
            "s": Something,
            "z": Something,
        }
        assert credential_definition.get("value").get("revocation") == {
            "g": Something,
            "g_dash": Something,
            "h": Something,
            "h0": Something,
            "h1": Something,
            "h2": Something,
            "h_cap": Something,
            "htilde": Something,
            "pk": Something,
            "u": Something,
            "y": Something,
        }

        credential_definition_id = credential_definition_state.get(
            "credential_definition_id"
        )
        assert credential_definition_id

        time.sleep(10)

        print("""
              +---------------------------------------------+
              |  Issuer checks revocation registry active   |
              +---------------------------------------------+
              """)
        resp = issuer.get_active_revocation_registry(credential_definition_id)

        assert resp == {
            "result": {
                "state": "finished",
                "record_id": Something,
                "cred_def_id": credential_definition_id,
                "issuer_did": issuer_did,
                "max_cred_num": Something,
                "revoc_def_type": "CL_ACCUM",
                "revoc_reg_id": Something,
                "revoc_reg_def": {
                    "ver": Something,
                    "id": Something,
                    "revocDefType": "CL_ACCUM",
                    "tag": Something,
                    "credDefId": Something,
                },
                "tag": Something,
                "tails_hash": Something,
                "tails_local_path": Something,
                "pending_pub": Something,
            }
        }

        print("""
              ###########################################
              #            Issue credential             #
              ###########################################
              """)
        print("""
              +-----------------------------------------+
              |  Issuer issues credential to holder     |
              +-----------------------------------------+
              """)
        resp = issuer.issue_credential(
            connection_id=issuer_connection_id,
            cred_def_id=credential_definition_id,
            issuer_id=issuer_did,
            schema_id=schema_id,
            attributes=[
                {"name": attribute_name, "value": f"{attribute_name}_val"}
                for attribute_name in schema_attribute_names
            ],
            comment="Auto generated credential for test",
        )

        issuer_cred_ex_id = resp.get("cred_ex_id")
        assert issuer_cred_ex_id

        time.sleep(10)

        print("""
              +-----------------------------------------+
              |       Holder gets cred_ex_id            |
              +-----------------------------------------+
              """)
        resp = holder.get_issue_records()

        records_results = resp.get("results")
        assert records_results
        assert type(records_results) is list
        assert len(issuer_connections_results) == 1

        [single_record] = records_results

        single_cred_ex_record = single_record.get("cred_ex_record")
        assert single_cred_ex_record

        assert single_cred_ex_record.get("state") == "offer-received"

        holder_cred_ex_id = single_cred_ex_record.get("cred_ex_id")
        assert holder_cred_ex_id

        print("""
              +-----------------------------------------+
              |  Holder accepts credential offer        |
              +-----------------------------------------+
              """)
        resp = holder.accept_credential_offer(holder_cred_ex_id)

        assert resp.get("cred_ex_id") == holder_cred_ex_id
        assert resp.get("state") == "request-sent"

        time.sleep(10)

        print("""
              +-----------------------------------------+
              |    Holder stores accepted credential    |
              +-----------------------------------------+
              """)
        local_credential_id = f"local_credential{int(time.time())}"

        holder.store_credential(
            cred_ex_id=holder_cred_ex_id, credential_id=local_credential_id
        )

        time.sleep(10)

        print("""
              ###########################################
              #    Present proof of valid credential    #
              ###########################################
              """)
        print("""
              +-----------------------------------------+
              | Issuer send presentation proof request  |
              +-----------------------------------------+
              """)
        resp = issuer.send_presentation_proof_request(
            connection_id=issuer_connection_id,
            cred_def_id=credential_definition_id,
            attributes=schema_attribute_names,
            version=schema_version,
            comment="Credential validation of holder should be valid",
        )

        assert resp.get("state") == "request-sent"

        time.sleep(10)

        print("""
              +-----------------------------------------+
              |    Holder retrieves pres exchange id    |
              +-----------------------------------------+
              """)
        resp = holder.get_presentation_proof_records()

        presentation_proof_records_results = resp.get("results")
        assert presentation_proof_records_results
        assert type(presentation_proof_records_results) is list
        assert len(presentation_proof_records_results) == 1

        [single_presentation_proof_records_result] = presentation_proof_records_results

        assert single_presentation_proof_records_result.get("state") == "request-received"

        holder_pres_ex_id = single_presentation_proof_records_result.get("pres_ex_id")
        assert holder_pres_ex_id

        print("""
              +-----------------------------------------+
              |   Holder accepts presentation request   |
              +-----------------------------------------+
              """)
        holder.accept_proof_request(
            pres_ex_id=holder_pres_ex_id,
            cred_id=local_credential_id,
            attributes=schema_attribute_names,
        )

        time.sleep(10)

        print("""
              +-----------------------------------------+
              |   Issuer checks presentation request    |
              +-----------------------------------------+
              """)
        resp = issuer.get_presentation_proof_records()

        presentation_proof_records_results = resp.get("results")
        assert presentation_proof_records_results
        assert type(presentation_proof_records_results) is list
        assert len(presentation_proof_records_results) == 1

        [single_presentation_proof_records_result] = presentation_proof_records_results

        assert single_presentation_proof_records_result.get("state") == "done"
        assert single_presentation_proof_records_result.get("verified") == "true"

        time.sleep(10)

        print("""
              #######################################################################
              #    Present proof of valid credential (with non-revocation proof)    #
              #######################################################################
              """)
        print("""
              +-----------------------------------------+
              | Issuer send presentation proof request  |
              +-----------------------------------------+
              """)
        resp = issuer.send_presentation_proof_request(
            connection_id=issuer_connection_id,
            cred_def_id=credential_definition_id,
            attributes=schema_attribute_names,
            version=schema_version,
            comment="Credential validation of holder should be valid with non-revocation proof",
            non_revoked={"to": int(time.time()) + 300},
        )

        assert resp.get("state") == "request-sent"

        time.sleep(10)

        print("""
              +-----------------------------------------+
              |    Holder retrieves pres exchange id    |
              +-----------------------------------------+
              """)
        resp = holder.get_presentation_proof_records(state="request-received")

        presentation_proof_records_results = resp.get("results")
        assert presentation_proof_records_results
        assert type(presentation_proof_records_results) is list
        assert len(presentation_proof_records_results) == 1

        [presentation_proof_record] = presentation_proof_records_results

        assert presentation_proof_record.get("state") == "request-received"

        holder_pres_ex_id = presentation_proof_record.get("pres_ex_id")
        assert holder_pres_ex_id

        print("""
              +-----------------------------------------+
              |   Holder accepts presentation request   |
              +-----------------------------------------+
              """)
        holder.accept_proof_request(
            pres_ex_id=holder_pres_ex_id,
            cred_id=local_credential_id,
            attributes=schema_attribute_names,
        )

        time.sleep(10)

        print("""
              +-----------------------------------------+
              |   Issuer checks presentation request    |
              +-----------------------------------------+
              """)
        resp = issuer.get_presentation_proof_records()

        presentation_proof_records_results = resp.get("results")
        assert presentation_proof_records_results
        assert type(presentation_proof_records_results) is list
        assert len(presentation_proof_records_results) == 2

        # List is not ordered
        presentation_proof_records_results.sort(key=lambda x: x.get("created_at"))

        [
            first_presentation_proof_records_result,
            second_presentation_proof_records_result,
        ] = presentation_proof_records_results

        assert first_presentation_proof_records_result.get("state") == "done"
        assert first_presentation_proof_records_result.get("verified") == "true"

        assert second_presentation_proof_records_result.get("state") == "done"
        assert second_presentation_proof_records_result.get("verified") == "true"

        time.sleep(10)

        print("""
              ###########################################
              #  Present proof of revoked credential    #
              ###########################################
              """)
        print("""
              +-----------------------------------------+
              |        Issuer revoke credential         |
              +-----------------------------------------+
              """)
        issuer.revoke_credential(
            cred_ex_id=issuer_cred_ex_id, comment="Test credential revocation"
        )

        time.sleep(10)

        print("""
              +-----------------------------------------+
              |  Issuer send presentation request       |
              +-----------------------------------------+
              """)
        issuer.send_presentation_proof_request(
            connection_id=issuer_connection_id,
            cred_def_id=credential_definition_id,
            attributes=schema_attribute_names,
            version=schema_version,
            comment="Credential validation of holder that is now revoked",
            non_revoked={"to": int(time.time()) + 300},
        )

        time.sleep(10)

        print("""
              +-----------------------------------------+
              |    Holder retrieves pres exchange id    |
              +-----------------------------------------+
              """)
        resp = holder.get_presentation_proof_records(state="request-received")

        presentation_proof_records_results = resp.get("results")
        assert presentation_proof_records_results
        assert type(presentation_proof_records_results) is list
        assert len(presentation_proof_records_results) == 1

        [single_presentation_proof_records_result] = presentation_proof_records_results

        assert single_presentation_proof_records_result.get("state") == "request-received"

        pres_ex_id = single_presentation_proof_records_result.get("pres_ex_id")
        assert pres_ex_id

        print("""
              +-----------------------------------------+
              |   Holder accepts presentation request   |
              +-----------------------------------------+
              """)
        holder.accept_proof_request(
            pres_ex_id=pres_ex_id,
            cred_id=local_credential_id,
            attributes=schema_attribute_names,
        )

        time.sleep(10)

        print("""
              +-----------------------------------------+
              |   Issuer checks presentation request    |
              +-----------------------------------------+
              """)

        resp = issuer.get_presentation_proof_records(state="done")

        presentation_proof_records_results = resp.get("results")
        assert presentation_proof_records_results
        assert type(presentation_proof_records_results) is list
        assert len(presentation_proof_records_results) == 3

        # List is not ordered
        presentation_proof_records_results.sort(key=lambda x: x.get("created_at"))

        [
            first_presentation_proof_records_result,
            second_presentation_proof_records_result,
            third_presentation_proof_records_result,
        ] = presentation_proof_records_results

        assert first_presentation_proof_records_result.get("state") == "done"
        assert first_presentation_proof_records_result.get("verified") == "true"

        assert second_presentation_proof_records_result.get("state") == "done"
        assert second_presentation_proof_records_result.get("verified") == "true"

        assert third_presentation_proof_records_result.get("state") == "done"
        assert third_presentation_proof_records_result.get("verified") == "false"
