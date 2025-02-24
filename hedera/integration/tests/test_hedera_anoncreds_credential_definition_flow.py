from time import sleep


class TestHederaAnonCredsCredentialDefinitionFlow:
    """Aggregate credential definition operation flows."""

    def test_flow(self, issuer, Something):
        """Test flow."""
        schema_name = "Example schema"
        schema_version = "1.0"
        schema_attribute_names = ["score"]
        key_type = "ed25519"
        key_type_capitalized = key_type.capitalize()
        credential_definition_tag = "default"

        issuer.create_wallet(persist_token=True)

        resp = issuer.register_did(key_type=key_type_capitalized)

        assert resp.get("key_type") == key_type

        did = resp.get("did")
        assert did

        resp = issuer.register_schema(
            name=schema_name,
            version=schema_version,
            attribute_names=schema_attribute_names,
            issuer_id=did,
        )

        assert "schema_state" in resp
        assert "schema_id" in resp.get("schema_state")

        schema_id = resp.get("schema_state").get("schema_id")

        assert schema_id

        sleep(10)

        resp = issuer.get_schema(schema_id)

        assert resp == {
            "schema": {
                "issuerId": did,
                "attrNames": schema_attribute_names,
                "name": schema_name,
                "version": schema_version,
            },
            "schema_id": schema_id,
            "resolution_metadata": {},
            "schema_metadata": {},
        }

        resp = issuer.register_credential_definition(
            schema_id=schema_id, issuer_id=did, tag=credential_definition_tag
        )

        assert "credential_definition_state" in resp
        assert "credential_definition_id" in resp.get("credential_definition_state")

        credential_definition_id = resp.get("credential_definition_state").get(
            "credential_definition_id"
        )

        assert credential_definition_id

        sleep(10)

        resp = issuer.get_credential_definition(credential_definition_id)

        assert resp == {
            "credential_definition": {
                "issuerId": did,
                "schemaId": schema_id,
                "tag": credential_definition_tag,
                "type": "CL",
                "value": {
                    "primary": {
                        "n": Something,
                        "s": Something,
                        "r": Something,
                        "rctxt": Something,
                        "z": Something,
                    },
                    "revocation": {
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
                    },
                },
            },
            "credential_definition_id": credential_definition_id,
            # Not returned from ACA-Py side
            # "credential_definition_metadata": {},
            "resolution_metadata": {},
        }
