"""Demo DID Web Issuance."""

import asyncio
import json
from os import getenv

from acapy_controller import Controller
from acapy_controller.logging import logging_to_stdout, section
from acapy_controller.protocols import (
    didexchange,
    indy_anoncred_credential_artifacts,
    anoncreds_issue_credential_v2,
)

AGENT = getenv("AGENT", "http://localhost:3001")
HOLDER = getenv("HOLDER", "http://localhost:3003")
logging_to_stdout()


async def main():
    async with Controller(AGENT) as controller, Controller(HOLDER) as holder:
        print("Retrieving Namespaces")
        ns_info = await controller.get("/did/indy/namespaces")
        print("Namespaces:", json.dumps(ns_info, indent=2))

        with section("Accept TAA"):
            print("Retrieving TAA")
            taa_info = await controller.post(
                "/did/indy/taa",
                json={
                    "namespace": "indicio:test",
                },
            )
            print("TAA:", json.dumps(taa_info, indent=2))

            print("Accepting TAA")
            taa_acceptance = await controller.post(
                "/did/indy/taa/accept",
                json={
                    # "taa_info": {
                    #     "namespace": "indicio:test",
                    #     "version": taa_info["version"],
                    #     "text": taa_info["text"],
                    # },
                    "taa_info": taa_info["taa"],
                    "mechanism": "on_file",
                    "namespace": "indicio:test",
                },
            )
            print("TAA Acceptance:", json.dumps(taa_acceptance, indent=2))

        with section("Create DID Indy"):
            print("Creating DID Indy")
            # Uncomment the following lines if you want to use indy_anoncred_onboard
            # This will create a new DID Indy and onboard it to the agent.
            # Note: This is not necessary if you already have a DID Indy created.
            did_indy_result = await controller.post(
                "/did/indy/new-did",
                json={
                    "namespace": "indicio:test",
                    "ldp_vc": True,
                    "didcomm": True,
                    # "nym": did.did,
                },
            )
            did_indy = did_indy_result["did"]
            vm = did_indy + "#assert"

        with section("Establish Connection"):
            agent_conn, holder_conn = await didexchange(controller, holder)

        with section("Register Schema"):
            print("Registering Schema and Credential Definition")
            print(f"Using DID: {did_indy}")
            print(f"Using Verifiable Method: {vm}")
            print("Did result:", json.dumps(did_indy_result, indent=2))
            schema, cred_def = await indy_anoncred_credential_artifacts(
                controller,
                ["firstname", "lastname"],
                support_revocation=False,
                issuer_id=did_indy,
            )
            # print(json.dumps(schema.serialize(), indent=2))
            # print(json.dumps(cred_def.serialize(), indent=2))

        with section("Issue Credential to Holder"):
            issuer_cred_ex, holder_cred_ex = await anoncreds_issue_credential_v2(
                controller,
                holder,
                agent_conn.connection_id,
                holder_conn.connection_id,
                cred_def.credential_definition_id,
                {"firstname": "Holder", "lastname": "test"},
            )
            # print(json.dumps(holder_cred_ex.serialize(), indent=2))
        print("Successfully issued credential to holder!")
        print("You can now use the issued credential in the holder agent.")
        print(
            "Holder Credential Exchange ID:", holder_cred_ex.cred_ex_record.cred_ex_id
        )
        print(
            "Issuer Credential Exchange ID:", issuer_cred_ex.cred_ex_record.cred_ex_id
        )
        print("Credential Definition ID:", cred_def.credential_definition_id)
        print("Schema ID:", schema.schema_id)
        print("DID Indy:", did_indy)
        print("Holder Credential Attributes:")
        print(
            json.dumps(
                holder_cred_ex.cred_ex_record.serialize()
                .get("by_format", {})
                .get("cred_issue", {})
                .get("anoncreds", {})
                .get("values", {}),
                indent=2,
            )
        )


if __name__ == "__main__":
    asyncio.run(main())
