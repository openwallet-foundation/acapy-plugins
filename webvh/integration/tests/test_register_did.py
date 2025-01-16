"""
Integration tests for the register DID protocol.
"""

import asyncio
from os import getenv
from typing import Optional

import pytest
from acapy_controller import Controller
from acapy_controller.controller import params
from acapy_controller.protocols import (
    ConnRecord,
    InvitationMessage,
    OobRecord,
    oob_invitation,
)

WITNESS = getenv("WITNESS", "http://witness:3001")
CONTROLLER_ENV = getenv("CONTROLLER", "http://controller:3001")


async def didexchange(
    inviter: Controller,
    invitee: Controller,
    *,
    invite: Optional[InvitationMessage] = None,
    use_existing_connection: bool = False,
    alias: Optional[str] = None,
):
    """Connect two agents using did exchange protocol."""
    if not invite:
        invite = await oob_invitation(inviter)

    invitee_oob_record = await invitee.post(
        "/out-of-band/receive-invitation",
        json=invite,
        params=params(
            use_existing_connection=use_existing_connection,
            alias=alias,
        ),
        response=OobRecord,
    )

    if use_existing_connection and invitee_oob_record == "reuse-accepted":
        inviter_oob_record = await inviter.event_with_values(
            topic="out_of_band",
            invi_msg_id=invite.id,
            event_type=OobRecord,
        )
        inviter_conn = await inviter.get(
            f"/connections/{inviter_oob_record.connection_id}",
            response=ConnRecord,
        )
        invitee_conn = await invitee.get(
            f"/connections/{invitee_oob_record.connection_id}",
            response=ConnRecord,
        )
        return inviter_conn, invitee_conn

    invitee_conn = await invitee.post(
        f"/didexchange/{invitee_oob_record.connection_id}/accept-invitation",
        response=ConnRecord,
    )
    inviter_oob_record = await inviter.event_with_values(
        topic="out_of_band",
        invi_msg_id=invite.id,
        state="done",
        event_type=OobRecord,
    )
    inviter_conn = await inviter.event_with_values(
        topic="connections",
        event_type=ConnRecord,
        rfc23_state="request-received",
        invitation_key=inviter_oob_record.our_recipient_key,
    )
    # TODO Remove after ACA-Py 0.12.0
    # There's a bug with race conditions in the OOB multiuse handling
    await asyncio.sleep(1)
    inviter_conn = await inviter.post(
        f"/didexchange/{inviter_conn.connection_id}/accept-request",
        response=ConnRecord,
    )

    await invitee.event_with_values(
        topic="connections",
        connection_id=invitee_conn.connection_id,
        rfc23_state="response-received",
    )
    invitee_conn = await invitee.event_with_values(
        topic="connections",
        connection_id=invitee_conn.connection_id,
        rfc23_state="completed",
        event_type=ConnRecord,
    )
    inviter_conn = await inviter.event_with_values(
        topic="connections",
        connection_id=inviter_conn.connection_id,
        rfc23_state="completed",
        event_type=ConnRecord,
    )

    return inviter_conn, invitee_conn


@pytest.mark.asyncio
async def test_create_with_witness():
    """Test Controller protocols."""
    async with (
        Controller(base_url=WITNESS) as witness,
        Controller(base_url=CONTROLLER_ENV) as controller,
    ):
        witness_config = (await witness.get("/status/config"))["config"]
        server_url = witness_config["plugin_config"]["did-webvh"]["server_url"]

        # Create the witness key for server auth
        await witness.post(
            "/wallet/keys",
            json={
                "seed": "00000000000000000000000000000000",
                "alg": "ed25519",
                "kid": "server.server:8000",
            },
        )

        # Create the connection with witness specific alias
        await didexchange(witness, controller, alias=f"{server_url}@Witness")

        # Create the initial did
        response = await controller.post(
            "/did/webvh/create",
            json={"options": {"namespace": "test"}},
        )

        assert response["did_document"]
        assert response["metadata"]["resolver"] == "WebvhDIDResolver"
        assert response["metadata"]["state"] == "posted"
