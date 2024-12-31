from unittest.mock import AsyncMock, patch

from acapy_agent.anoncreds.base import (
        AnonCredsSchema as AcapyAnonCredsSchema,
        GetSchemaResult as AcapyGetSchemaResult,
        GetCredDefResult as AcapyGetCredDefResult,
        CredDef as AcapyAnonCredsCredDef,
    )

from acapy_agent.anoncreds.models.credential_definition import (
        CredDefValue as AcapyAnonCredsCredDefValue,
        CredDefValuePrimary as AcapyAnonCredsCredDefValuePrimary,
        CredDefValueRevocation as AcapyAnonCredsCredDefValueRevocation,
        )
from did_sdk_py.anoncreds import (
        CredDefValue as HederaCredDefValue,
        CredDefValuePrimary as HederaCredDefValuePrimary,
        CredDefValueRevocation as HederaCredDefValueRevocation
        )

from hedera_did.anoncreds_registry import HederaAnonCredsRegistry

from did_sdk_py.anoncreds.types import (
        GetSchemaResult as HederaGetSchemaResult,
        AnonCredsSchema as HederaAnonCredsSchema,
        GetCredDefResult as HederaGetCredDefResult,
        AnonCredsCredDef as HederaAnonCredsCredDef,
     )

class TestAnonCredsRegistryRegistry:
    @patch("hedera_did.anoncreds_registry.SdkHederaAnonCredsRegistry")
    async def test_get_schema(self, mock_hedera_did_anoncreds_registry, profile, context):
        schema_id = "did:hedera:testnet:zFwZUYPrhi333pC2anAnSkctXgZzLfeR8DXURo2N4xV1C_0.0.5284925/anoncreds/v0/SCHEMA/0.0.5284932"

        acapy_get_schema_result = AcapyGetSchemaResult(
                schema_id='did:hedera:testnet:zFwZUYPrhi333pC2anAnSkctXgZzLfeR8DXURo2N4xV1C_0.0.5284925/anoncreds/v0/SCHEMA/0.0.5284932',
                resolution_metadata={},
                schema_metadata={},
                schema=AcapyAnonCredsSchema(
                    name='Example schema 18-12-2024',
                    issuer_id='did:hedera:testnet:zFwZUYPrhi333pC2anAnSkctXgZzLfeR8DXURo2N4xV1C_0.0.5284925',
                    attr_names=['score'],
                    version='1.0')
                )

        hedera_get_schema_result = HederaGetSchemaResult(
                schema_id="did:hedera:testnet:zFwZUYPrhi333pC2anAnSkctXgZzLfeR8DXURo2N4xV1C_0.0.5284925/anoncreds/v0/SCHEMA/0.0.5284932",
                resolution_metadata={},
                schema_metadata={},
                schema=HederaAnonCredsSchema(
                    name='Example schema 18-12-2024',
                    issuer_id='did:hedera:testnet:zFwZUYPrhi333pC2anAnSkctXgZzLfeR8DXURo2N4xV1C_0.0.5284925',
                    attr_names=['score'],
                    version='1.0')
                )

        registry = HederaAnonCredsRegistry()
        await registry.setup(context)

        mock_hedera_did_anoncreds_registry.return_value.get_schema = AsyncMock(return_value = hedera_get_schema_result)

        resp = await registry.get_schema(profile, schema_id)

        assert acapy_get_schema_result.schema_metadata == resp.schema_metadata
        assert acapy_get_schema_result.schema_id == resp.schema_id
        assert acapy_get_schema_result.resolution_metadata == resp.resolution_metadata

        assert acapy_get_schema_result.schema

        assert acapy_get_schema_result.schema.issuer_id == resp.schema.issuer_id
        assert acapy_get_schema_result.schema.attr_names == resp.schema.attr_names
        assert acapy_get_schema_result.schema.name == resp.schema.name
        assert acapy_get_schema_result.schema.version == resp.schema.version
        

    @patch("hedera_did.anoncreds_registry.SdkHederaAnonCredsRegistry")
    async def test_get_credential_definition(self, mock_hedera_did_anoncreds_registry, profile, context):
        credential_definition_id = "did:hedera:testnet:zcZMJMxUGZpxKmP35ACBWLhQyQVqtRc5T7LQhdyTDtEiP_0.0.5280965/anoncreds/v0/PUBLIC_CRED_DEF/0.0.5280968"

        acapy_get_cred_def_result = AcapyGetCredDefResult(
                credential_definition_id='did:hedera:testnet:zcZMJMxUGZpxKmP35ACBWLhQyQVqtRc5T7LQhdyTDtEiP_0.0.5280965/anoncreds/v0/PUBLIC_CRED_DEF/0.0.5280968',
                resolution_metadata={},
                credential_definition_metadata={},
                credential_definition=AcapyAnonCredsCredDef(
                    type="CL",
                    issuer_id='did:hedera:testnet:zcZMJMxUGZpxKmP35ACBWLhQyQVqtRc5T7LQhdyTDtEiP_0.0.5280965',
                    schema_id='did:hedera:testnet:zcZMJMxUGZpxKmP35ACBWLhQyQVqtRc5T7LQhdyTDtEiP_0.0.5280965/anoncreds/v0/SCHEMA/0.0.5280967',
                    tag='demo-cred-def-1.0', 
                    value=AcapyAnonCredsCredDefValue(
                        primary=AcapyAnonCredsCredDefValuePrimary(
                            n='0954456694171',
                            s='0954456694171',
                            r={'key': 'value'}, 
                            rctxt='0954456694171',
                            z='0954456694171'
                            ),
                        revocation=AcapyAnonCredsCredDefValueRevocation(
                            g='1 1F14F&ECB578F 2 095E45DDF417D',
                            g_dash='1 1D64716fCDC00C 1 0C781960FA66E3D3 2 095E45DDF417D',
                            h='1 16675DAE54BFAE8 2 095E45DD417D',
                            h0='1 21E5EF9476EAF18 2 095E45DDF417D',
                            h1='1 236D1D99236090 2 095E45DDF417D',
                            h2='1 1C3AE8D1F1E277 2 095E45DDF417D',
                            htilde='1 1D8549E8C0F8 2 095E45DDF417D',
                            h_cap='1 1B2A32CF3167 1 2490FEBF6EE55 1 0000000000000000',
                            u='1 0C430AAB2B4710 1 1CB3A0932EE7E 1 0000000000000000',
                            pk='1 142CD5E5A7DC 1 153885BD903312 2 095E45DDF417D',
                            y='1 153558BD903312 2 095E45DDF417D 1 0000000000000000'
                            )
                        )
                    )
                )

        hedera_get_cred_def_result = HederaGetCredDefResult(
                credential_definition_id="did:hedera:testnet:zcZMJMxUGZpxKmP35ACBWLhQyQVqtRc5T7LQhdyTDtEiP_0.0.5280965/anoncreds/v0/PUBLIC_CRED_DEF/0.0.5280968",
                resolution_metadata={},
                credential_definition_metadata={},
                credential_definition=HederaAnonCredsCredDef(
                    issuer_id="did:hedera:testnet:zcZMJMxUGZpxKmP35ACBWLhQyQVqtRc5T7LQhdyTDtEiP_0.0.5280965",
                    schema_id="did:hedera:testnet:zcZMJMxUGZpxKmP35ACBWLhQyQVqtRc5T7LQhdyTDtEiP_0.0.5280965/anoncreds/v0/SCHEMA/0.0.5280967",
                    tag="demo-cred-def-1.0",
                    value=HederaCredDefValue(
                        primary=HederaCredDefValuePrimary(
                            n="0954456694171",
                            s="0954456694171",
                            r={"key":"value"},
                            rctxt= "0954456694171",
                            z= "0954456694171"
                            ),
                        revocation=HederaCredDefValueRevocation(
                            g= "1 1F14F&ECB578F 2 095E45DDF417D",
                            g_dash= "1 1D64716fCDC00C 1 0C781960FA66E3D3 2 095E45DDF417D",
                            h= "1 16675DAE54BFAE8 2 095E45DD417D",
                            h0= "1 21E5EF9476EAF18 2 095E45DDF417D",
                            h1= "1 236D1D99236090 2 095E45DDF417D",
                            h2= "1 1C3AE8D1F1E277 2 095E45DDF417D",
                            htilde= "1 1D8549E8C0F8 2 095E45DDF417D",
                            h_cap= "1 1B2A32CF3167 1 2490FEBF6EE55 1 0000000000000000",
                            u= "1 0C430AAB2B4710 1 1CB3A0932EE7E 1 0000000000000000",
                            pk= "1 142CD5E5A7DC 1 153885BD903312 2 095E45DDF417D",
                            y= "1 153558BD903312 2 095E45DDF417D 1 0000000000000000"
                            )
                        )
                    )
                )

        registry = HederaAnonCredsRegistry()
        await registry.setup(context)

        mock_hedera_did_anoncreds_registry.return_value.get_cred_def = AsyncMock(return_value = hedera_get_cred_def_result)

        resp = await registry.get_credential_definition(profile, credential_definition_id)

        assert acapy_get_cred_def_result.credential_definition_id == resp.credential_definition_id
        assert acapy_get_cred_def_result.resolution_metadata == resp.resolution_metadata
        assert acapy_get_cred_def_result.credential_definition_metadata == resp.credential_definition_metadata
        assert acapy_get_cred_def_result.credential_definition.issuer_id == resp.credential_definition.issuer_id
        assert acapy_get_cred_def_result.credential_definition.schema_id == resp.credential_definition.schema_id
        assert acapy_get_cred_def_result.credential_definition.tag == resp.credential_definition.tag
        assert acapy_get_cred_def_result.credential_definition.value.primary.n == resp.credential_definition.value.primary.n
        assert acapy_get_cred_def_result.credential_definition.value.primary.s == resp.credential_definition.value.primary.s
        assert acapy_get_cred_def_result.credential_definition.value.primary.r == resp.credential_definition.value.primary.r
        assert acapy_get_cred_def_result.credential_definition.value.primary.rctxt == resp.credential_definition.value.primary.rctxt
        assert acapy_get_cred_def_result.credential_definition.value.primary.z == resp.credential_definition.value.primary.z
        assert acapy_get_cred_def_result.credential_definition.value.revocation is not None
        assert resp.credential_definition.value.revocation is not None
        assert acapy_get_cred_def_result.credential_definition.value.revocation.g == resp.credential_definition.value.revocation.g
        assert acapy_get_cred_def_result.credential_definition.value.revocation.g_dash == resp.credential_definition.value.revocation.g_dash
        assert acapy_get_cred_def_result.credential_definition.value.revocation.h == resp.credential_definition.value.revocation.h
        assert acapy_get_cred_def_result.credential_definition.value.revocation.h0 == resp.credential_definition.value.revocation.h0
        assert acapy_get_cred_def_result.credential_definition.value.revocation.h1 == resp.credential_definition.value.revocation.h1
        assert acapy_get_cred_def_result.credential_definition.value.revocation.h2 == resp.credential_definition.value.revocation.h2
        assert acapy_get_cred_def_result.credential_definition.value.revocation.htilde == resp.credential_definition.value.revocation.htilde
        assert acapy_get_cred_def_result.credential_definition.value.revocation.h_cap == resp.credential_definition.value.revocation.h_cap
        assert acapy_get_cred_def_result.credential_definition.value.revocation.u == resp.credential_definition.value.revocation.u
        assert acapy_get_cred_def_result.credential_definition.value.revocation.pk == resp.credential_definition.value.revocation.pk
        assert acapy_get_cred_def_result.credential_definition.value.revocation.y == resp.credential_definition.value.revocation.y

