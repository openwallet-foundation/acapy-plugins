"""Modified connection record."""

import json
from typing import Union

from acapy_agent.connections.models.conn_record import (
    ConnRecord,
    MaybeStoredConnRecordSchema,
    OOBInvitation,
)
from acapy_agent.core.profile import ProfileSession
from acapy_agent.storage.base import BaseStorage
from marshmallow import fields, validate

from connections.v1_0.messages.connection_invitation import ConnectionInvitation
from connections.v1_0.messages.connection_request import ConnectionRequest


class ConnectionsRecord(ConnRecord):
    """Modified connection record for use with connections protocol."""

    class Meta:
        """ConnectionsRecord metadata."""

        schema_class = "MaybeStoredConnectionsRecordSchema"

    SUPPORTED_PROTOCOLS = ("connections/1.0", *ConnRecord.SUPPORTED_PROTOCOLS)

    async def attach_invitation(
        self,
        session: ProfileSession,
        invitation: Union[ConnectionInvitation, OOBInvitation],
    ):
        """Attach invitation."""
        return await super().attach_invitation(session, invitation)

    async def retrieve_invitation(self, session: ProfileSession) -> ConnectionInvitation:
        """Retrieve invitation."""
        assert self.connection_id
        storage = session.inject(BaseStorage)
        result = await storage.find_record(
            self.RECORD_TYPE_INVITATION,
            {"connection_id": self.connection_id},
        )
        ser = json.loads(result.value)
        if ser.get("@type") == "https://didcomm.org/out-of-band/1.1/invitation":
            return OOBInvitation.deserialize(ser)
        return ConnectionInvitation.deserialize(ser)

    async def attach_request(self, session: ProfileSession, request: ConnectionRequest):
        """Attach request."""
        return await super().attach_request(session, request)

    async def retrieve_request(self, session: ProfileSession) -> ConnectionRequest:
        """Retrieve request."""
        assert self.connection_id
        storage: BaseStorage = session.inject(BaseStorage)
        result = await storage.find_record(
            self.RECORD_TYPE_REQUEST, {"connection_id": self.connection_id}
        )
        ser = json.loads(result.value)
        return ConnectionRequest.deserialize(ser)


class MaybeStoredConnectionsRecordSchema(MaybeStoredConnRecordSchema):
    """Schema."""

    connection_protocol = fields.Str(
        required=False, validate=validate.OneOf(ConnectionsRecord.SUPPORTED_PROTOCOLS)
    )
