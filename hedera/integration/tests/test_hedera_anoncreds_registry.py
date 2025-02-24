class TestHederaAnonCredsRegistry:
    def test_get_schema(self, holder):
        issuer_id = (
            "did:hedera:testnet:zFwZUYPrhi333pC2anAnSkctXgZzLfeR8DXURo2N4xV1C_0.0.5284925"
        )
        schema_id = f"{issuer_id}/anoncreds/v0/SCHEMA/0.0.5284932"

        holder.create_wallet(persist_token=True)

        response = holder.get_schema(schema_id)

        assert response == {
            "schema_metadata": {},
            "resolution_metadata": {},
            "schema_id": schema_id,
            "schema": {
                "issuerId": issuer_id,
                "attrNames": ["score"],
                "name": "Example schema 18-12-2024",
                "version": "1.0",
            },
        }

    def test_get_credential_definition(self, holder):
        issuer_id = (
            "did:hedera:testnet:zcZMJMxUGZpxKmP35ACBWLhQyQVqtRc5T7LQhdyTDtEiP_0.0.5280965"
        )
        schema_id = f"{issuer_id}/anoncreds/v0/SCHEMA/0.0.5280967"
        credential_definition_id = f"{issuer_id}/anoncreds/v0/PUBLIC_CRED_DEF/0.0.5280968"

        holder.create_wallet(persist_token=True)

        response = holder.get_credential_definition(credential_definition_id)

        assert response == {
            # Not returned from ACA-Py side
            # "credential_definition_metadata": {},
            "resolution_metadata": {},
            "credential_definition_id": credential_definition_id,
            "credential_definition": {
                "issuerId": issuer_id,
                "schemaId": schema_id,
                "tag": "demo-cred-def-1.0",
                "type": "CL",
                "value": {
                    "primary": {
                        "n": "0954456694171",
                        "s": "0954456694171",
                        "r": {"key": "value"},
                        "rctxt": "0954456694171",
                        "z": "0954456694171",
                    },
                    "revocation": {
                        "g": "1 1F14F&ECB578F 2 095E45DDF417D",
                        "g_dash": "1 1D64716fCDC00C 1 0C781960FA66E3D3 2 095E45DDF417D",
                        "h": "1 16675DAE54BFAE8 2 095E45DD417D",
                        "h0": "1 21E5EF9476EAF18 2 095E45DDF417D",
                        "h1": "1 236D1D99236090 2 095E45DDF417D",
                        "h2": "1 1C3AE8D1F1E277 2 095E45DDF417D",
                        "htilde": "1 1D8549E8C0F8 2 095E45DDF417D",
                        "h_cap": "1 1B2A32CF3167 1 2490FEBF6EE55 1 0000000000000000",
                        "u": "1 0C430AAB2B4710 1 1CB3A0932EE7E 1 0000000000000000",
                        "pk": "1 142CD5E5A7DC 1 153885BD903312 2 095E45DDF417D",
                        "y": "1 153558BD903312 2 095E45DDF417D 1 0000000000000000",
                    },
                },
            },
        }
