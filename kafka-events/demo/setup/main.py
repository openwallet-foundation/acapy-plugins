"""Automate setup of Agency + Mediator:

1. Create invitation from mediator
2. Receive invitation in Agency
3. Request mediation from mediator
4. Set mediator as default
"""

import asyncio
from os import getenv
from typing import Any, Callable, TypeVar

from acapy_client import Client
from acapy_client.api.connection import (
    get_connection,
    receive_invitation,
    create_invitation,
)
from acapy_client.api.mediation import (
    get_mediation_requests_mediation_id,
    post_mediation_request_conn_id,
    put_mediation_mediation_id_default_mediator,
)
from acapy_client.models.conn_record import ConnRecord
from acapy_client.models.connection_invitation import ConnectionInvitation
from acapy_client.models.create_invitation_request import CreateInvitationRequest
from acapy_client.models.mediation_create_request import MediationCreateRequest
from acapy_client.models.mediation_record import MediationRecord
from acapy_client.models.receive_invitation_request import ReceiveInvitationRequest

AGENT = getenv("AGENT_ADMIN_URL")
MEDIATOR = getenv("MEDIATOR_ADMIN_URL")


RecordType = TypeVar("RecordType", bound=Any)


async def wait_for_state(
    record: RecordType, state: str, retrieve: Callable
) -> RecordType:
    while record.state != state:
        await asyncio.sleep(1)
        record = await retrieve(record)
        assert record

    return record


async def get_mediator_invite(mediator: Client) -> dict:
    invite = await create_invitation.asyncio(
        client=mediator, json_body=CreateInvitationRequest()
    )
    if not invite:
        raise RuntimeError("Failed to retrieve invitation from mediator")

    assert isinstance(invite.invitation, ConnectionInvitation)
    return invite.invitation.to_dict()


async def agent_receive_invitation(agent: Client, invite: dict) -> ConnRecord:
    conn_record = await receive_invitation.asyncio(
        client=agent, json_body=ReceiveInvitationRequest.from_dict(invite)
    )
    if not conn_record:
        raise RuntimeError("Failed to receive invitation on agent")

    async def _retrieve(record: ConnRecord):
        assert isinstance(record.connection_id, str)
        return await get_connection.asyncio(record.connection_id, client=agent)

    return await wait_for_state(conn_record, "active", _retrieve)


async def agent_request_mediation(agent: Client, conn_id: str):
    mediation_record = await post_mediation_request_conn_id.asyncio(
        conn_id=conn_id, client=agent, json_body=MediationCreateRequest()
    )
    if not mediation_record:
        raise RuntimeError(f"Failed to request mediation from {conn_id}")

    async def _retrieve(record: MediationRecord):
        assert isinstance(record.mediation_id, str)
        return await get_mediation_requests_mediation_id.asyncio(
            record.mediation_id, client=agent
        )

    return await wait_for_state(mediation_record, "granted", _retrieve)


async def agent_set_default_mediator(agent: Client, mediation_id: str):
    result = await put_mediation_mediation_id_default_mediator.asyncio(
        mediation_id, client=agent
    )
    if not result:
        raise RuntimeError(f"Failed to set default mediator to {mediation_id}")
    return result


async def main():
    if not AGENT or not MEDIATOR:
        raise RuntimeError(
            "Must set environment variables AGENT_ADMIN_URL and MEDIATOR_ADMIN_URL"
        )

    agent = Client(base_url=AGENT)
    mediator = Client(base_url=MEDIATOR)

    mediator_invite = await get_mediator_invite(mediator)
    conn_record = await agent_receive_invitation(agent, mediator_invite)
    print("Mediator and agent are now connected.")
    print(f"Agent connection id: {conn_record.connection_id}")

    assert conn_record
    assert isinstance(conn_record.connection_id, str)
    mediation_record = await agent_request_mediation(agent, conn_record.connection_id)
    print("Mediator has granted mediation to agent.")
    print(f"Mediation id: {mediation_record.mediation_id}")

    assert mediation_record
    assert isinstance(mediation_record.mediation_id, str)
    await agent_set_default_mediator(agent, mediation_record.mediation_id)

    print("Proxy mediator is now default mediator for agent.")


if __name__ == "__main__":
    asyncio.run(main())
