import time

class TestHederaAnonCredsFlow:
    def test_schema_flow(self, bob, Something):
        timestamp = time.time()
        schema_name = f"Example schema {timestamp}"

        response  = bob.register_did({"key_type": "Ed25519"})

        assert response.status_code == 200
        
        response_body = response.json()
        
        assert response_body.get("key_type") == "ed25519"

        did = response_body.get("did")

        response = bob.register_schema({
            "schema": {
                "attrNames": ["score"],
                "issuerId": did,
                "name": schema_name,
                "version": "1.0"
                }
            })

        assert response.status_code == 200
        response_body = response.json()

        assert 'schema_state' in response_body
        assert 'schema_id' in response_body.get('schema_state')

        schema_id = response_body.get('schema_state').get('schema_id')

        time.sleep(5)

        response = bob.get_schema(schema_id)

        assert response.status_code == 200
        assert response.json() == {
          "schema": {
            "issuerId": did,
            "attrNames": [
              "score"
            ],
            "name": schema_name,
            "version": "1.0"
          },
          "schema_id": schema_id,
          "resolution_metadata": {},
          "schema_metadata": {}
        }

        response = bob.register_credential_definition({
            "credential_definition": {
                "issuerId": did,
                "schemaId": schema_id,
                "tag": "default"
                }
            })

        response_body = response.json()

        assert 'credential_definition_state' in response_body
        assert 'credential_definition_id' in response_body.get('credential_definition_state')

        credential_definition_id = response_body.get('credential_definition_state').get('credential_definition_id')

        time.sleep(5)

        response = bob.get_credential_definition(credential_definition_id)

        assert response.status_code == 200
        assert response.json() == {
                "credential_definition": {
                    "issuerId": did,
                    "schemaId": schema_id,
                    "tag": "default",
                    "type": "CL",
                    "value": {
                        "primary": {
                            "n": Something,
                            "s": Something,
                            "r": Something,
                            "rctxt": Something,
                            "z": Something,
                            },
                        }
                    },
                "credential_definition_id": credential_definition_id,
                # "credential_definition_metadata": {}, # FIXME Acapy is not returning this item, why not?
                "resolution_metadata": {},
                }
