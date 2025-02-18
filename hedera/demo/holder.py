import asyncio
import json
import os
import time

from integration.tests.helpers import Agent

from .utils.menu import Fail, Menu, MenuEntry, Ok, PressResult
from .utils.print import clear_screen, notify, notify_json
from .utils.prompt import prompt
from .utils.webhook_listener import WebHookListener


# Global variables used so they can be called between different menu entries
# or webhook events. Also used for assessing state, e.g. have we established
# a connection or not
AGENT = Agent(
    name="agent-holder",
    base_url="http://agent-holder:3001",
)
CONNECTION_ID = None
LOCAL_CREDENTIAL_ID = None


class HolderWebHookHandler:
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

    async def handle_connection_reuse_accepted(self, message):
        pass

    async def handle_issue_credential_v2_0(self, message):
        state = message["state"]
        cred_ex_id = message["cred_ex_id"]

        if state == "offer-received":
            notify(prefix="CREDENTIAL", msg="Accepting credential offer")
            AGENT.accept_credential_offer(cred_ex_id=cred_ex_id)

        elif state == "credential-received":
            notify(prefix="CREDENTIAL", msg="Storing credential")

            global LOCAL_CREDENTIAL_ID
            LOCAL_CREDENTIAL_ID = f"credential_{int(time.time())}"

            AGENT.store_credential(
                cred_ex_id=cred_ex_id, credential_id=LOCAL_CREDENTIAL_ID
            )

    async def handle_issue_credential_v2_0_anoncreds(self, message):
        if "cred_id_stored" in message:
            credential_id = message["cred_id_stored"]

            notify(
                prefix="CREDENTIAL", msg=f"Stored credential {credential_id} in wallet"
            )

            resp = AGENT.get_credential(credential_id)

            notify_json(resp)

    async def handle_present_proof_v2_0(self, message):
        state = message["state"]

        if state == "request-received":
            if not LOCAL_CREDENTIAL_ID:
                notify(prefix="ERROR", msg="No credential in local storage")
                return

            pres_ex_id = message["pres_ex_id"]
            requested_attributes_obj = message["by_format"]["pres_request"]["anoncreds"][
                "requested_attributes"
            ]
            attribute_names = list(requested_attributes_obj.keys())

            notify(prefix="PROOF-PRESENTATION", msg="Request received")
            notify(prefix="PROOF-PRESENTATION", msg="Sending proof...")

            AGENT.accept_proof_request(
                pres_ex_id=pres_ex_id,
                cred_id=LOCAL_CREDENTIAL_ID,
                attributes=attribute_names,
            )
        elif state == "done":
            notify(prefix="PROOF-PRESENTATION", msg="Presentation done")


def _setup():
    notify(prefix="SETUP 1/2", msg="Setup webhook listener")
    WebHookListener(webhook_handler=HolderWebHookHandler()).listen_webhooks()

    notify(prefix="SETUP 2/2", msg="Create multi-tenant wallet")
    AGENT.create_wallet(persist_token=True)


async def _interaction_loop():
    async def entrypoint():
        menu = Menu(
            title="Main Holder menu",
            entries=[
                MenuEntry(key="3", description="Send message", on_press=_send_message),
                MenuEntry(
                    key="4",
                    description="Input new invitation",
                    on_press=_receive_invitation,
                ),
            ],
        )

        await menu.user_interact()

    async def _send_message() -> PressResult:
        if not CONNECTION_ID:
            return Fail("No connection is set up")

        message = await prompt("message: ")
        AGENT.send_message(connection_id=CONNECTION_ID, message=message)

        return Ok()

    async def _receive_invitation() -> PressResult:
        invitation = await prompt("Invitation:")

        if not invitation:
            raise Exception("No invitation object")

        invitation_obj = json.loads(invitation)

        resp = AGENT.receive_invitation(invitation_obj)

        global CONNECTION_ID
        CONNECTION_ID = resp["connection_id"]

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
