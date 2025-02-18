import asyncio
import json
import os
import time

from qrcode import QRCode

from integration.tests.helpers import Agent

from .utils.menu import Fail, Menu, MenuEntry, Ok, PressResult
from .utils.print import clear_screen, notify
from .utils.prompt import prompt
from .utils.webhook_listener import WebHookListener


# Global variables used so they can be called between different menu entries
# or webhook events. Also used for assessing state, e.g. have we established
# a connection or not
AGENT = Agent(
    name="agent-issuer",
    base_url="http://agent-issuer:3001",
)
CONNECTION_ID = None
DID = None
SCHEMA_ID = None
CRED_DEF_ID = None
CRED_EX_ID = None
NGROK_ENDPOINT = os.getenv("NGROK_ENDPOINT", None)


class IssuerWebHookHandler:
    async def handle_basicmessages(self, message):
        content = message["content"]
        notify(prefix="MESSAGE", msg=content)

    async def handle_connections(self, message):
        connection_state = message["state"]

        if connection_state == "active":
            global CONNECTION_ID
            CONNECTION_ID = message["connection_id"]

            notify(prefix="CONNECTED", msg=f"connection_id: {CONNECTION_ID}")

    async def handle_out_of_band(self, message):
        pass

    async def handle_connection_reuse(self, message):
        pass

    async def handle_issue_credential_v2_0(self, message):
        pass

    async def handle_issue_credential_v2_0_anoncreds(self, message):
        pass

    async def handle_issuer_cred_rev(self, message):
        pass

    async def handle_present_proof_v2_0(self, message):
        state = message["state"]

        if state == "request-sent":
            notify(prefix="PROOF-PRESENTATION", msg="Request sent")

        if state == "done":
            is_verified = message["verified"]

            notify(prefix="PROOF-PRESENTATION", msg=f"Proof is valid: {is_verified}")


def _setup():
    notify(prefix="SETUP 1/5", msg="Setup webhook listener")
    WebHookListener(webhook_handler=IssuerWebHookHandler()).listen_webhooks()

    notify(prefix="SETUP 2/5", msg="Create multi-tenant wallet")
    AGENT.create_wallet(persist_token=True)

    notify(prefix="SETUP 3/5", msg="Register DID on Hedera")
    resp = AGENT.register_did(key_type="Ed25519")

    global DID
    DID = resp["did"]

    notify(prefix="SETUP 4/5", msg="Register schema")
    resp = AGENT.register_schema(
        name="Example demo schema",
        version="1.0",
        issuer_id=DID,
        attribute_names=["name", "age"],
    )

    global SCHEMA_ID
    SCHEMA_ID = resp["schema_state"]["schema_id"]

    time.sleep(10)

    notify(prefix="SETUP 5/5", msg="Register credential definition")
    resp = AGENT.register_credential_definition(
        schema_id=SCHEMA_ID, issuer_id=DID, tag="default"
    )

    global CRED_DEF_ID
    CRED_DEF_ID = resp["credential_definition_state"]["credential_definition_id"]


async def _interaction_loop():
    async def entrypoint():
        menu = Menu(
            title="Main Issuer menu",
            entries=[
                MenuEntry(
                    key="1", description="Issue credential", on_press=_issue_credential
                ),
                MenuEntry(
                    key="2",
                    description="Send Proof Request",
                    on_press=_send_proof_request,
                ),
                MenuEntry(key="3", description="Send Message", on_press=_send_message),
                MenuEntry(
                    key="4",
                    description="Create New Invitation",
                    on_press=_create_invitation,
                ),
                MenuEntry(
                    key="5", description="Revoke credential", on_press=_revoke_credential
                ),
            ],
        )

        await menu.press_key("4")

        await menu.user_interact()

    async def _issue_credential() -> PressResult:
        if not CONNECTION_ID:
            return Fail("No connection is set up")

        if not DID or not CRED_DEF_ID or not SCHEMA_ID:
            return Fail("Setup process not successful")

        resp = AGENT.issue_credential(
            connection_id=CONNECTION_ID,
            cred_def_id=CRED_DEF_ID,
            issuer_id=DID,
            schema_id=SCHEMA_ID,
            attributes=[
                {"name": "name", "value": "John Smith"},
                {"name": "age", "value": "18"},
            ],
            comment="Demo credential",
        )

        global CRED_EX_ID
        CRED_EX_ID = resp["cred_ex_id"]

        return Ok()

    async def _send_proof_request() -> PressResult:
        if not CONNECTION_ID:
            return Fail("No connection is set up")

        if not CRED_DEF_ID:
            return Fail("Setup process not successful")

        AGENT.send_presentation_proof_request(
            CONNECTION_ID,
            cred_def_id=CRED_DEF_ID,
            attributes=["name", "age"],
            version="1.0",
            comment="Demo proof request",
            non_revoked={"to": int(time.time()) + 300},
        )

        return Ok()

    async def _send_message() -> PressResult:
        if not CONNECTION_ID:
            return Fail("No connection is set up")

        message = await prompt("message: ")
        AGENT.send_message(connection_id=CONNECTION_ID, message=message)

        return Ok()

    async def _create_invitation() -> PressResult:
        resp = AGENT.create_invitation(
            alias="Holder connection",
            goal="Test functionality in demo scenario",
            label="Demo issuer",
        )

        invitation_url = resp["invitation_url"]

        if NGROK_ENDPOINT:
            invitation_url = invitation_url.replace(
                "http://agent-issuer:3000", NGROK_ENDPOINT
            )

        qr = QRCode(border=1)
        qr.add_data(invitation_url)
        qr.print_ascii(invert=True)

        invitation = resp["invitation"]

        return Ok(f"Invitation object:\n{json.dumps(invitation)}")

    async def _revoke_credential() -> PressResult:
        if not CRED_EX_ID:
            return Fail("Setup process not successful")

        AGENT.revoke_credential(cred_ex_id=CRED_EX_ID, comment="Revoke demo credential")

        notify(prefix="REVOCATION", msg="Credential has been revoked")

        return Ok()

    await entrypoint()


async def main():
    clear_screen()

    _setup()

    await _interaction_loop()


if __name__ == "__main__":
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        asyncio.get_event_loop().run_until_complete(main())
    except KeyboardInterrupt:
        os._exit(1)
