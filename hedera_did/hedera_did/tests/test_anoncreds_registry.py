from unittest.mock import AsyncMock, patch

from did_sdk_py.anoncreds import (
    CredDefValue as HederaCredDefValue,
    CredDefValuePrimary as HederaCredDefValuePrimary,
    CredDefValueRevocation as HederaCredDefValueRevocation,
)
from did_sdk_py.anoncreds.types import (
    AnonCredsCredDef as HederaAnonCredsCredDef,
    AnonCredsSchema as HederaAnonCredsSchema,
    GetCredDefResult as HederaGetCredDefResult,
    GetSchemaResult as HederaGetSchemaResult,
)
from hedera_did.anoncreds_registry import HederaAnonCredsRegistry

class TestAnonCredsRegistry:
    @patch("hedera_did.anoncreds_registry.SdkHederaAnonCredsRegistry")
    async def test_get_schema(self, mock_hedera_did_anoncreds_registry, profile, context):
        schema_id = "did:hedera:testnet:zFwZUYPrhi333pC2anAnSkctXgZzLfeR8DXURo2N4xV1C_0.0.5284925/anoncreds/v0/SCHEMA/0.0.5284932"
        issuer_id = "did:hedera:testnet:zFwZUYPrhi333pC2anAnSkctXgZzLfeR8DXURo2N4xV1C_0.0.5284925"
        version = "1.0"
        name = "Example schema"
        attr_names = ["score"]

        mock_hedera_did_anoncreds_registry.return_value.get_schema = AsyncMock(
                return_value = HederaGetSchemaResult(
                    schema_id=schema_id,
                    resolution_metadata={},
                    schema_metadata={},
                    schema=HederaAnonCredsSchema(
                        name=name,
                        issuer_id=issuer_id,
                        attr_names=attr_names,
                        version=version
                        )
                    )
                )

        registry = HederaAnonCredsRegistry()
        await registry.setup(context)

        resp = await registry.get_schema(profile, schema_id)

        assert resp.serialize() == {
                "schema_id": schema_id,
                "resolution_metadata": {
                    },
                "schema_metadata": {
                    },
                "schema": {
                        "name": name,
                        "issuerId": issuer_id,
                        "attrNames": attr_names,
                        "version": version
                    }
                }


    @patch("hedera_did.anoncreds_registry.SdkHederaAnonCredsRegistry")
    async def test_get_credential_definition(self, mock_hedera_did_anoncreds_registry, profile, context):
        credential_definition_id = "did:hedera:testnet:zcZMJMxUGZpxKmP35ACBWLhQyQVqtRc5T7LQhdyTDtEiP_0.0.5280965/anoncreds/v0/PUBLIC_CRED_DEF/0.0.5280968"
        type_ = "CL"
        issuer_id="did:hedera:testnet:zcZMJMxUGZpxKmP35ACBWLhQyQVqtRc5T7LQhdyTDtEiP_0.0.5280965"
        schema_id = "did:hedera:testnet:zcZMJMxUGZpxKmP35ACBWLhQyQVqtRc5T7LQhdyTDtEiP_0.0.5280965/anoncreds/v0/SCHEMA/0.0.5280967"
        tag = "demo-cred-def-1.0"
        n = "0954456694171"
        s = "0954456694171"
        r = {"key": "value"}
        rctxt = "0954456694171"
        z = "0954456694171"
        g ="1 1F14F&ECB578F 2 095E45DDF417D"
        g_dash ="1 1D64716fCDC00C 1 0C781960FA66E3D3 2 095E45DDF417D"
        h ="1 16675DAE54BFAE8 2 095E45DD417D"
        h0 ="1 21E5EF9476EAF18 2 095E45DDF417D"
        h1 ="1 236D1D99236090 2 095E45DDF417D"
        h2 ="1 1C3AE8D1F1E277 2 095E45DDF417D"
        htilde ="1 1D8549E8C0F8 2 095E45DDF417D"
        h_cap ="1 1B2A32CF3167 1 2490FEBF6EE55 1 0000000000000000"
        u ="1 0C430AAB2B4710 1 1CB3A0932EE7E 1 0000000000000000"
        pk ="1 142CD5E5A7DC 1 153885BD903312 2 095E45DDF417D"
        y ="1 153558BD903312 2 095E45DDF417D 1 0000000000000000"

        mock_hedera_did_anoncreds_registry.return_value.get_cred_def = AsyncMock(
                return_value = HederaGetCredDefResult(
                credential_definition_id=credential_definition_id,
                resolution_metadata={},
                credential_definition_metadata={},
                credential_definition=HederaAnonCredsCredDef(
                    issuer_id=issuer_id,
                    schema_id=schema_id,
                    tag=tag,
                    value=HederaCredDefValue(
                        primary=HederaCredDefValuePrimary(
                            n=n,
                            s=s,
                            r=r,
                            rctxt=rctxt,
                            z=z,
                            ),
                        revocation=HederaCredDefValueRevocation(
                            g=g,
                            g_dash=g_dash,
                            h=h,
                            h0=h0,
                            h1=h1,
                            h2=h2,
                            htilde=htilde,
                            h_cap=h_cap,
                            u=u,
                            pk=pk,
                            y=y,
                            )
                        )
                    )
                )
            )

        registry = HederaAnonCredsRegistry()
        await registry.setup(context)

        resp = await registry.get_credential_definition(profile, credential_definition_id)

        assert resp.serialize() == {
                "credential_definition_id": credential_definition_id,
                "resolution_metadata": {},
                # "credential_definition_metadata": {}, # FIXME Acapy is not returning this item, why not?
                "credential_definition": {
                    "issuerId": issuer_id,
                    "schemaId": schema_id,
                    "tag": tag,
                    "type": type_,
                    "value": {
                        "primary": {
                            "n": n,
                            "s": s,
                            "r": r,
                            "rctxt": rctxt,
                            "z": z,
                            },
                        "revocation": {
                            "g": g,
                            "g_dash": g_dash,
                            "h": h,
                            "h0": h0,
                            "h1": h1,
                            "h2": h2,
                            "htilde": htilde,
                            "h_cap": h_cap,
                            "u": u,
                            "pk": pk,
                            "y": y,
                            }
                        }
                    }
                }
