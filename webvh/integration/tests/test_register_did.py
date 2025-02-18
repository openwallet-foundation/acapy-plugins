"""
Integration tests for the register DID protocol.
"""

import asyncio
from typing import Optional

import pytest
import uuid
from acapy_controller import Controller
from acapy_controller.controller import params
from acapy_controller.protocols import (
    ConnRecord,
    InvitationMessage,
    OobRecord,
    oob_invitation,
)

from .constants import (
    WITNESS_SEED,
    WITNESS_KEY,
    WITNESS_KID,
    WEBVH_DOMAIN,
    WITNESS,
    TEST_NAMESPACE,
    CONTROLLER_ENV
)


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
async def test_create_single_tenant():
    """Test Controller protocols."""
    async with (
        Controller(base_url=WITNESS) as witness,
    ):
        witness_config = (await witness.get("/status/config"))["config"]
        server_url = witness_config["plugin_config"]["did-webvh"]["server_url"]

        # # Assign kid to witness key
        # try:
        #     await witness.put(
        #         "/wallet/keys",
        #         json={
        #             "multikey": WITNESS_KEY,
        #             "kid": WITNESS_KID,
        #         },
        #     )
        # except:
        #     pass

        # # Esure the witness key is properly configured
        # response = await witness.get(
        #     f"/wallet/keys/{WITNESS_KEY}"
        # )
        # assert response['kid'] == WITNESS_KID

        # Configure WebVH Witness
        response = await witness.post(
            "/did/webvh/configuration",
            json={
                'server_url': server_url,
                'witness_key': WITNESS_KEY,
                'witness': True
            },
        )
        assert response['witness_key'] == WITNESS_KEY

        # Esure the witness key is properly configured
        response = await witness.get(
            f"/wallet/keys/{WITNESS_KEY}"
        )
        assert response['kid'] == WITNESS_KID
        
        # Create the initial did
        identifier = str(uuid.uuid4())
        response = await witness.post(
            "/did/webvh/create",
            json={"options": {"namespace": TEST_NAMESPACE, 'identifier': identifier}},
        )
        
        # TODO, fix did webvh resolving
        # assert response["did_document"]
        # assert response["metadata"]["resolver"] == "WebvhDIDResolver"
        # assert response["metadata"]["state"] == "posted"
        
        # Confirm DID is published
        did_web = f'did:web:{WEBVH_DOMAIN}:{TEST_NAMESPACE}:{identifier}'
        response = await witness.get(
            f"/resolver/resolve/{did_web}"
        )
        assert response["did_document"]['id'] == did_web
        assert response["did_document"]['alsoKnownAs'][0].startswith('did:webvh:')


@pytest.mark.asyncio
async def test_create_with_witness():
    """Test Controller protocols."""
    async with (
        Controller(base_url=WITNESS) as witness,
        Controller(base_url=CONTROLLER_ENV) as controller,
    ):
        witness_config = (await witness.get("/status/config"))["config"]
        server_url = witness_config["plugin_config"]["did-webvh"]["server_url"]

        # Configure WebVH Witness
        response = await witness.post(
            "/did/webvh/configuration",
            json={
                'server_url': server_url,
                'witness_key': WITNESS_KEY,
                'witness': True
            },
        )
        assert response['witness_key'] == WITNESS_KEY

        # Esure the witness key is properly configured
        response = await witness.get(
            f"/wallet/keys/{WITNESS_KEY}"
        )
        assert response['kid'] == WITNESS_KID

        # Create the connection with witness specific alias
        witness_alias = f"{server_url}@witness"
        await didexchange(witness, controller, alias=witness_alias)
        response = await controller.get(
            f"/connections?alias={witness_alias}"
        )
        assert response['results'][0]['state'] == 'active'

        # Create the initial did
        identifier = str(uuid.uuid4())
        response = await controller.post(
            "/did/webvh/create",
            json={"options": {"namespace": TEST_NAMESPACE, "identifier": identifier}},
        )
        # response = await witness.get(
        #     "/did/webvh/witness/pending"
        # )
        # assert response['results']
        # await asyncio.sleep(5)

#         # assert response["did_document"]
#         # assert response["metadata"]["resolver"] == "WebvhDIDResolver"
#         # assert response["metadata"]["state"] == "posted"
        
        # Confirm DID is published
        # did_web = f'did:web:{WEBVH_DOMAIN}:{TEST_NAMESPACE}:{identifier}'
        # response = await controller.get(
        #     f"/resolver/resolve/{did_web}"
        # )
        # assert response["did_document"]['id'] == did_web
        # assert response["did_document"]['alsoKnownAs'][0].startswith('did:webvh:')
