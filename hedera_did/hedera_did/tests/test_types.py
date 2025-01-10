from acapy_agent.anoncreds.base import (
    AnonCredsSchema as AcapyAnonCredsSchema,
    CredDef as AcapyAnonCredsCredDef,
    RevRegDef as AcapyRevRegDef,
)
from acapy_agent.anoncreds.models.credential_definition import (
    CredDefValue as AcapyCredDefValue,
    CredDefValuePrimary as AcapyCredDefValuePrimary,
    CredDefValueRevocation as AcapyCredDefValueRevocation,
)
from acapy_agent.anoncreds.models.revocation import (
    RevRegDefValue as AcapyRevRegDefValue,
)
from did_sdk_py.anoncreds.models import (
    CredDefValue as HederaCredDefValue,
    CredDefValuePrimary as HederaCredDefValuePrimary,
    CredDefValueRevocation as HederaCredDefValueRevocation,
    RevRegDefValue as HederaRevRegDefValue,
)
from did_sdk_py.anoncreds.models.schema import AnonCredsSchema as HederaAnonCredsSchema
from did_sdk_py.anoncreds.types import (
    AnonCredsCredDef as HederaAnonCredsCredDef,
    AnonCredsRevList as HederaAnonCredsRevList,
    AnonCredsRevRegDef as HederaAnonCredsRevRegDef,
    CredDefState as HederaCredDefState,
    GetCredDefResult as HederaGetCredDefResult,
    GetRevRegDefResult as HederaGetRevRegDefResult,
    RegisterCredDefResult as HederaCredDefResult,
    RegisterRevListResult as HederaRegisterRevListResult,
    RegisterSchemaResult as HederaSchemaResult,
    RevListState as HederaRevListState,
    SchemaState as HederaSchemaState,
)
from hedera_did.types import (
    buildAcapyCredDefResult,
    buildAcapyGetRevRegDefResult,
    buildAcapyRevListResult,
    buildAcapySchemaResult,
    buildHederaAnonCredsCredDef,
    buildHederaAnonCredsRevRegDef,
    buildHederaAnonCredsSchema,
)

class TestTypes:
    def testBuildHederaAnonCredsSchema(self):
        name = "Example schema"
        issuer_id = "did:hedera:testnet:zFwZUYPrhi333pC2anAnSkctXgZzLfeR8DXURo2N4xV1C_0.0.5284925"
        attr_names = ["score"]
        version = "1.0"

        assert buildHederaAnonCredsSchema(
                AcapyAnonCredsSchema(
                    name=name,
                    issuer_id=issuer_id,
                    attr_names=attr_names,
                    version=version
                    )
                ) == HederaAnonCredsSchema(
                    name=name,
                    issuer_id=issuer_id,
                    attr_names=attr_names,
                    version=version
                    )


    def testBuildHederaAnonCredsCredDef(self):
        issuer_id = "did:hedera:testnet:zFwZUYPrhi333pC2anAnSkctXgZzLfeR8DXURo2N4xV1C_0.0.5284925"
        schema_id = f"{issuer_id}/anoncreds/v0/SCHEMA/0.0.5284932"
        tag="default"
        type_="CL"
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

        assert buildHederaAnonCredsCredDef(
                AcapyAnonCredsCredDef(
                    issuer_id=issuer_id,
                    schema_id=schema_id,
                    type=type_,
                    tag=tag,
                    value=AcapyCredDefValue(
                        primary=AcapyCredDefValuePrimary(
                            n=n,
                            s=s,
                            r=r,
                            rctxt=rctxt,
                            z=z
                            ),
                        revocation=AcapyCredDefValueRevocation(
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
                            y=y
                            )
                        )
                    )
                ) == HederaAnonCredsCredDef(
                        issuer_id=issuer_id,
                        schema_id=schema_id,
                        tag=tag,
                        value=HederaCredDefValue(
                            primary=HederaCredDefValuePrimary(
                                n= n,
                                s= s,
                                r= r,
                                rctxt= rctxt,
                                z= z
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

    def testBuildAcapyGetCredDefResult(self):
        resolution_metadata = {}
        credential_definition_metadata = {}
        credential_definition_id = "did:hedera:testnet:zcZMJMxUGZpxKmP35ACBWLhQyQVqtRc5T7LQhdyTDtEiP_0.0.5280965/anoncreds/v0/PUBLIC_CRED_DEF/0.0.5280968"
        issuer_id = "did:hedera:testnet:zFwZUYPrhi333pC2anAnSkctXgZzLfeR8DXURo2N4xV1C_0.0.5284925"
        schema_id = f"{issuer_id}/anoncreds/v0/SCHEMA/0.0.5284932"
        tag="default"
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

        acapy_get_cred_def_result = HederaGetCredDefResult(
                    resolution_metadata=resolution_metadata,
                    credential_definition_metadata=credential_definition_metadata,
                    credential_definition_id=credential_definition_id,
                    credential_definition=HederaAnonCredsCredDef(
                        issuer_id=issuer_id,
                        schema_id=schema_id,
                        tag=tag,
                        value=HederaCredDefValue(
                            primary=HederaCredDefValuePrimary(
                                n= n,
                                s= s,
                                r= r,
                                rctxt= rctxt,
                                z= z
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

        assert acapy_get_cred_def_result.resolution_metadata == resolution_metadata
        assert acapy_get_cred_def_result.credential_definition_metadata == credential_definition_metadata
        assert acapy_get_cred_def_result.credential_definition_id == credential_definition_id
        assert acapy_get_cred_def_result.credential_definition
        assert acapy_get_cred_def_result.credential_definition.issuer_id == issuer_id
        assert acapy_get_cred_def_result.credential_definition.schema_id == schema_id
        assert acapy_get_cred_def_result.credential_definition.tag == tag
        assert acapy_get_cred_def_result.credential_definition.value.primary.n == n
        assert acapy_get_cred_def_result.credential_definition.value.primary.s == s
        assert acapy_get_cred_def_result.credential_definition.value.primary.r == r
        assert acapy_get_cred_def_result.credential_definition.value.primary.rctxt == rctxt
        assert acapy_get_cred_def_result.credential_definition.value.primary.z == z
        assert acapy_get_cred_def_result.credential_definition.value.revocation
        assert acapy_get_cred_def_result.credential_definition.value.revocation.g == g
        assert acapy_get_cred_def_result.credential_definition.value.revocation.g_dash == g_dash
        assert acapy_get_cred_def_result.credential_definition.value.revocation.h == h
        assert acapy_get_cred_def_result.credential_definition.value.revocation.h0 == h0
        assert acapy_get_cred_def_result.credential_definition.value.revocation.h1 == h1
        assert acapy_get_cred_def_result.credential_definition.value.revocation.h2 == h2
        assert acapy_get_cred_def_result.credential_definition.value.revocation.htilde == htilde
        assert acapy_get_cred_def_result.credential_definition.value.revocation.h_cap == h_cap
        assert acapy_get_cred_def_result.credential_definition.value.revocation.u == u
        assert acapy_get_cred_def_result.credential_definition.value.revocation.pk == pk
        assert acapy_get_cred_def_result.credential_definition.value.revocation.y == y

    def testBuildAcapySchemaResult(self):
        registration_metadata = {}
        schema_metadata = {}
        name = "Example schema"
        issuer_id = "did:hedera:testnet:zFwZUYPrhi333pC2anAnSkctXgZzLfeR8DXURo2N4xV1C_0.0.5284925"
        schema_id = f"{issuer_id}/anoncreds/v0/SCHEMA/0.0.5284932"
        attr_names = ["score"]
        version = "1.0"
        state = "finished"
        reason = "reason"

        acapy_schema_result = buildAcapySchemaResult(
            HederaSchemaResult(
                registration_metadata=registration_metadata,
                schema_metadata=schema_metadata,
                schema_state=HederaSchemaState(
                    state=state,
                    schema=HederaAnonCredsSchema(
                        name=name,
                        issuer_id=issuer_id,
                        attr_names=attr_names,
                        version=version
                        ),
                    schema_id=schema_id,
                    reason=reason
                    )
                )
            )

        assert acapy_schema_result.registration_metadata == registration_metadata
        assert acapy_schema_result.schema_metadata == schema_metadata
        assert acapy_schema_result.job_id is None
        assert acapy_schema_result.schema_state.state == state
        assert acapy_schema_result.schema_state.schema_id == schema_id
        assert acapy_schema_result.schema_state.schema.issuer_id == issuer_id
        assert acapy_schema_result.schema_state.schema.attr_names == attr_names
        assert acapy_schema_result.schema_state.schema.name == name
        assert acapy_schema_result.schema_state.schema.version == version


    def testBuildAcapyCredDefResult(self):
        registration_metadata = {}
        credential_definition_metadata = {}
        credential_definition_id = "did:hedera:testnet:zcZMJMxUGZpxKmP35ACBWLhQyQVqtRc5T7LQhdyTDtEiP_0.0.5280965/anoncreds/v0/PUBLIC_CRED_DEF/0.0.5280968"
        issuer_id = "did:hedera:testnet:zFwZUYPrhi333pC2anAnSkctXgZzLfeR8DXURo2N4xV1C_0.0.5284925"
        schema_id = f"{issuer_id}/anoncreds/v0/SCHEMA/0.0.5284932"
        tag="default"
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
        state = "finished"
        reason = "reason"

        acapy_cred_def_result = buildAcapyCredDefResult(
                HederaCredDefResult(
                    registration_metadata=registration_metadata,
                    credential_definition_metadata=credential_definition_metadata,
                    credential_definition_state=HederaCredDefState(
                        state=state,
                        credential_definition=HederaAnonCredsCredDef(
                            issuer_id=issuer_id,
                            schema_id=schema_id,
                            tag=tag,
                            value=HederaCredDefValue(
                                primary=HederaCredDefValuePrimary(
                                    n= n,
                                    s= s,
                                    r= r,
                                    rctxt= rctxt,
                                    z= z
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
                            ),
                        credential_definition_id=credential_definition_id,
                        reason=reason
                        )
                    )
                )

        assert acapy_cred_def_result.registration_metadata == registration_metadata
        assert acapy_cred_def_result.credential_definition_metadata == credential_definition_metadata
        assert acapy_cred_def_result.credential_definition_state.state == state
        assert acapy_cred_def_result.credential_definition_state.credential_definition.issuer_id == issuer_id
        assert acapy_cred_def_result.credential_definition_state.credential_definition.schema_id == schema_id
        assert acapy_cred_def_result.credential_definition_state.credential_definition.tag == tag
        assert acapy_cred_def_result.credential_definition_state.credential_definition.value.primary.n == n
        assert acapy_cred_def_result.credential_definition_state.credential_definition.value.primary.s == s
        assert acapy_cred_def_result.credential_definition_state.credential_definition.value.primary.r == r
        assert acapy_cred_def_result.credential_definition_state.credential_definition.value.primary.rctxt == rctxt
        assert acapy_cred_def_result.credential_definition_state.credential_definition.value.primary.z == z
        assert acapy_cred_def_result.credential_definition_state.credential_definition.value.revocation
        assert acapy_cred_def_result.credential_definition_state.credential_definition.value.revocation.g == g
        assert acapy_cred_def_result.credential_definition_state.credential_definition.value.revocation.g_dash == g_dash
        assert acapy_cred_def_result.credential_definition_state.credential_definition.value.revocation.h == h
        assert acapy_cred_def_result.credential_definition_state.credential_definition.value.revocation.h0 == h0
        assert acapy_cred_def_result.credential_definition_state.credential_definition.value.revocation.h1 == h1
        assert acapy_cred_def_result.credential_definition_state.credential_definition.value.revocation.h2 == h2
        assert acapy_cred_def_result.credential_definition_state.credential_definition.value.revocation.htilde == htilde
        assert acapy_cred_def_result.credential_definition_state.credential_definition.value.revocation.h_cap == h_cap
        assert acapy_cred_def_result.credential_definition_state.credential_definition.value.revocation.u == u
        assert acapy_cred_def_result.credential_definition_state.credential_definition.value.revocation.pk == pk
        assert acapy_cred_def_result.credential_definition_state.credential_definition.value.revocation.y == y


    def testBuildAcapyRevListResult(self):
        registration_metadata = {}
        revocation_list_metadata = {}
        issuer_id = "did:hedera:testnet:zFwZUYPrhi333pC2anAnSkctXgZzLfeR8DXURo2N4xV1C_0.0.5284925"
        rev_reg_def_id = f"{issuer_id}/anoncreds/v0/REV_REG/0.0.5281064"
        state = "finished"
        reason = "reason"
        revocation_list = [0, 1, 1, 0]
        current_accumulator = "21118FFB"
        timestamp = 1735318300

        acapy_rev_list_result = buildAcapyRevListResult(
                HederaRegisterRevListResult(
                    registration_metadata=registration_metadata,
                    revocation_list_metadata=revocation_list_metadata,
                    revocation_list_state=HederaRevListState(
                        state=state,
                        revocation_list=HederaAnonCredsRevList(
                            issuer_id=issuer_id,
                            rev_reg_def_id=rev_reg_def_id,
                            revocation_list=revocation_list,
                            current_accumulator=current_accumulator,
                            timestamp=timestamp
                            ),
                        reason=reason
                        ),
                    )
                )

        assert acapy_rev_list_result.registration_metadata == registration_metadata
        assert acapy_rev_list_result.revocation_list_metadata == revocation_list_metadata
        assert acapy_rev_list_result.revocation_list_state.state == state
        assert acapy_rev_list_result.revocation_list_state.revocation_list.issuer_id == issuer_id
        assert acapy_rev_list_result.revocation_list_state.revocation_list.rev_reg_def_id == rev_reg_def_id
        assert acapy_rev_list_result.revocation_list_state.revocation_list.revocation_list == revocation_list
        assert acapy_rev_list_result.revocation_list_state.revocation_list.current_accumulator == current_accumulator
        assert acapy_rev_list_result.revocation_list_state.revocation_list.timestamp == timestamp


    def testBuildAcapyRevRegDefResult(self):
        issuer_id = "did:hedera:testnet:zFwZUYPrhi333pC2anAnSkctXgZzLfeR8DXURo2N4xV1C_0.0.5284925"
        cred_def_id = "did:hedera:testnet:zcZMJMxUGZpxKmP35ACBWLhQyQVqtRc5T7LQhdyTDtEiP_0.0.5280965/anoncreds/v0/PUBLIC_CRED_DEF/0.0.5280968"
        rev_reg_def_id = f"{issuer_id}/anoncreds/v0/REV_REG/0.0.5281064"
        resolution_metadata = {}
        revocation_registry_definition_metadata= {}
        tag = "demo-cred-def-1.0"
        public_keys={}
        max_cred_num = 999
        tails_location = "./location/to/tails"
        tails_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

        acapy_get_rev_reg_def_result = buildAcapyGetRevRegDefResult(
            HederaGetRevRegDefResult(
                revocation_registry_definition_id=rev_reg_def_id,
                resolution_metadata=resolution_metadata,
                revocation_registry_definition_metadata=revocation_registry_definition_metadata,
                revocation_registry_definition = HederaAnonCredsRevRegDef(
                    issuer_id=issuer_id,
                    cred_def_id=cred_def_id,
                    tag=tag,
                    value=HederaRevRegDefValue(
                        public_keys=public_keys,
                        max_cred_num=max_cred_num,
                        tails_location=tails_location,
                        tails_hash=tails_hash
                        )
                    )
                )
        )

        assert acapy_get_rev_reg_def_result.revocation_registry_id == rev_reg_def_id
        assert acapy_get_rev_reg_def_result.resolution_metadata == resolution_metadata
        assert acapy_get_rev_reg_def_result.revocation_registry_metadata == revocation_registry_definition_metadata
        assert acapy_get_rev_reg_def_result.revocation_registry.issuer_id == issuer_id
        assert acapy_get_rev_reg_def_result.revocation_registry.cred_def_id == cred_def_id
        assert acapy_get_rev_reg_def_result.revocation_registry.tag == tag
        assert acapy_get_rev_reg_def_result.revocation_registry.value.public_keys == public_keys
        assert acapy_get_rev_reg_def_result.revocation_registry.value.max_cred_num == max_cred_num
        assert acapy_get_rev_reg_def_result.revocation_registry.value.tails_location == tails_location
        assert acapy_get_rev_reg_def_result.revocation_registry.value.tails_hash == tails_hash

    def testBuildHederaAnonCredsRevRegDef(self):
        issuer_id = "did:hedera:testnet:zFwZUYPrhi333pC2anAnSkctXgZzLfeR8DXURo2N4xV1C_0.0.5284925"
        type_="CL_ACCUM"
        cred_def_id = "did:hedera:testnet:zcZMJMxUGZpxKmP35ACBWLhQyQVqtRc5T7LQhdyTDtEiP_0.0.5280965/anoncreds/v0/PUBLIC_CRED_DEF/0.0.5280968"
        tag = "demo-cred-def-1.0"
        public_keys={}
        max_cred_num = 999
        tails_location = "./location/to/tails"
        tails_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

        hedera_anon_creds_rev_reg_def = buildHederaAnonCredsRevRegDef(
                AcapyRevRegDef(
                    issuer_id=issuer_id,
                    type=type_,
                    cred_def_id=cred_def_id,
                    tag=tag,
                    value=AcapyRevRegDefValue(
                        public_keys=public_keys,
                        max_cred_num=max_cred_num,
                        tails_location=tails_location,
                        tails_hash=tails_hash
                        )
                    )
                )

        assert hedera_anon_creds_rev_reg_def.issuer_id == issuer_id
        assert hedera_anon_creds_rev_reg_def.cred_def_id == cred_def_id
        assert hedera_anon_creds_rev_reg_def.tag == tag
        assert hedera_anon_creds_rev_reg_def.value.public_keys == public_keys
        assert hedera_anon_creds_rev_reg_def.value.max_cred_num == max_cred_num
        assert hedera_anon_creds_rev_reg_def.value.tails_location == tails_location
        assert hedera_anon_creds_rev_reg_def.value.tails_hash == tails_hash
