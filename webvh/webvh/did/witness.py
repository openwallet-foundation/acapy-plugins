"""Module to manage witnesses for a DID."""

import copy
import logging
from typing import Optional

from acapy_agent.connections.models.conn_record import ConnRecord
from acapy_agent.core.profile import Profile
from acapy_agent.messaging.responder import BaseResponder
from acapy_agent.protocols.out_of_band.v1_0.manager import (
    OutOfBandManager,
    OutOfBandManagerError,
)
from acapy_agent.protocols.out_of_band.v1_0.messages.invitation import (
    HSProto,
)

from ..config.config import get_plugin_config, get_server_domain

from .exceptions import WitnessError
from ..protocols.attested_resource.record import PendingAttestedResourceRecord
from ..protocols.attested_resource.messages import (
    WitnessRequest as AttestedResourceWitnessRequest,
    WitnessResponse as AttestedResrouceWitnessResponse,
)
from ..protocols.log_entry.record import PendingLogEntryRecord
from ..protocols.log_entry.messages import (
    WitnessRequest as LogEntryWitnessRequest,
    WitnessResponse as LogEntryWitnessResponse,
)
from ..protocols.states import WitnessingState
from ..did.server_client import WebVHServerClient
from ..did.utils import decode_invitation, find_key, add_proof

LOGGER = logging.getLogger(__name__)


class WitnessManager:
    """Class to manage witnesses for a DID."""

    def __init__(self, profile: Profile):
        """Initialize the witness manager."""
        self.profile = profile
        self.server_client = WebVHServerClient(profile)
        self.proof_options = {
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "proofPurpose": "assertionMethod",
        }

    async def key_alias(self) -> str:
        """Derive witness key alias."""
        domain = await get_server_domain(self.profile)
        return f"webvh:{domain}@witnessKey"

    async def connection_alias(self) -> str:
        """Derive witness connection alias."""
        domain = await get_server_domain(self.profile)
        return f"webvh:{domain}@witness"

    async def _get_active_witness_connection(self) -> Optional[ConnRecord]:
        """Find the active witness connection.

        Primarily looks the connection up by its `invitation_msg_id` tag,
        which is indexed on ConnRecord (set by DIDXManager to the OOB
        invitation's `@id` when the connection is created). This is an
        O(1) lookup regardless of how many connection records exist in
        the wallet, rather than a scan. The invitation message id itself
        is derived from the plugin's configured `witness_invitation` URL,
        the same static config already required to create the connection
        automatically, so nothing needs to be cached or persisted
        separately.

        Falls back to an alias lookup, narrowed by the indexed `state`
        tag, only when no witness invitation is configured (or it wasn't
        matched) -- this supports connections that were set up manually
        by an operator (see the log message in `manager.auto_witness_setup`)
        rather than via the automatic invitation flow, a rare/administrative
        path where a state-narrowed lookup is an acceptable trade-off.
        """
        active_state = ConnRecord.State.COMPLETED.rfc160

        invitation_msg_id = await self._witness_invitation_msg_id()
        if invitation_msg_id:
            async with self.profile.session() as session:
                connection_records = await ConnRecord.query(
                    session, tag_filter={"invitation_msg_id": invitation_msg_id}
                )
            for connection in connection_records:
                if connection.state == active_state:
                    return connection

        witness_alias = await self.connection_alias()
        async with self.profile.session() as session:
            connection_records = await ConnRecord.query(
                session,
                tag_filter={"state": active_state},
                post_filter_positive={"alias": witness_alias},
            )

        return connection_records[0] if connection_records else None

    async def _witness_invitation_msg_id(self) -> Optional[str]:
        """Get the invitation message id of the configured witness invitation."""
        witness_invitation = (await get_plugin_config(self.profile)).get(
            "witness_invitation"
        )
        if not witness_invitation:
            return None

        return decode_invitation(witness_invitation).get("@id")

    async def get_witness_key(self) -> str:
        """Return the witness key."""
        witness_alias = await self.key_alias()
        witness_key = await find_key(self.profile, witness_alias)
        if not witness_key:
            raise WitnessError(f"Witness key [{witness_alias}] not found.")

        return witness_key

    async def witness_log_entry(
        self,
        scid: str,
        log_entry: dict,
        request_id: str,
    ) -> Optional[dict]:
        """Witness the document with the given parameters."""
        config = await get_plugin_config(self.profile)

        # Self witness
        if config.get("witness", False):
            record = PendingLogEntryRecord()
            if config.get("auto_attest", False):
                return await self.sign_log_version(log_entry.get("versionId"))

            # Self-witnessing: no connection_id, role is self-witness
            await record.save_pending_record(
                self.profile,
                scid,
                log_entry,
                request_id,
                connection_id="",
                role="self-witness",
            )

        # Need proof from witness agent
        else:
            responder = self.profile.inject(BaseResponder)

            witness_connection = await self._get_active_witness_connection()
            if not witness_connection:
                raise WitnessError("No active witness connection found.")

            await responder.send(
                message=LogEntryWitnessRequest(document=log_entry, request_id=request_id),
                connection_id=witness_connection.connection_id,
            )

    async def witness_attested_resource(
        self,
        scid: str,
        attested_resource: dict,
        request_id: str,
    ) -> Optional[dict]:
        """Witness the document with the given parameters."""
        config = await get_plugin_config(self.profile)

        # Self witness
        if config.get("witness", False):
            record = PendingAttestedResourceRecord()
            if config.get("auto_attest", False):
                witness_key = await self.get_witness_key()
                return await add_proof(
                    self.profile,
                    attested_resource,
                    f"did:key:{witness_key}#{witness_key}",
                )
            # Self-witnessing: no connection_id, role is self-witness
            await record.save_pending_record(
                self.profile,
                scid,
                attested_resource,
                request_id,
                connection_id="",
                role="self-witness",
            )

        # Need proof from witness agent
        else:
            responder = self.profile.inject(BaseResponder)

            witness_connection = await self._get_active_witness_connection()
            if not witness_connection:
                raise WitnessError("No active witness connection found.")

            await responder.send(
                message=AttestedResourceWitnessRequest(
                    document=attested_resource, request_id=request_id
                ),
                connection_id=witness_connection.connection_id,
            )

    async def sign_log_version(self, version_id) -> dict:
        """Sign a given log versionId with a DataIntegrityProof."""
        witness_key = await self.get_witness_key()
        witness_signature = await add_proof(
            self.profile,
            {"versionId": version_id},
            f"did:key:{witness_key}#{witness_key}",
        )
        return witness_signature

    async def approve_log_entry(
        self, log_entry: dict, connection_id: str, request_id: str = None
    ) -> dict[str, str]:
        """Attest a did request doc."""

        if not log_entry.get("proof", None):
            raise WitnessError("No proof found in log entry. Cannot witness.")

        witness_key = await self.get_witness_key()
        witness_signature = await add_proof(
            self.profile,
            {"versionId": log_entry.get("versionId")},
            f"did:key:{witness_key}#{witness_key}",
        )

        if not connection_id:
            # NOTE: will have to review this behavior when witness threshold is > 1
            # is supported
            from ..did.manager import ControllerManager

            await ControllerManager(self.profile).finish_did_operation(
                log_entry, witness_signature
            )
        else:
            await self.profile.inject(BaseResponder).send(
                message=LogEntryWitnessResponse(
                    state=WitnessingState.ATTESTED.value,
                    document=log_entry,
                    witness_proof=witness_signature.get("proof")[0],
                    request_id=request_id,
                ),
                connection_id=connection_id,
            )

        return {"status": "success", "message": "Witness successful."}

    async def approve_attested_resource(
        self, attested_resource: dict, connection_id: str = None, request_id: str = None
    ) -> dict[str, str]:
        """Approve an attested resource."""

        if not attested_resource.get("proof", None):
            raise WitnessError("No proof found in log entry. Cannot witness.")

        witness_key = await self.get_witness_key()
        witnessed_resource = await add_proof(
            self.profile,
            copy.deepcopy(attested_resource),
            f"did:key:{witness_key}#{witness_key}",
        )

        if not connection_id:
            # Upload resource to server
            author_id = attested_resource.get("id").split("/")[0]
            namespace = author_id.split(":")[4]
            identifier = author_id.split(":")[5]
            await self.server_client.upload_attested_resource(
                namespace, identifier, witnessed_resource
            )
            return attested_resource
        else:
            await self.profile.inject(BaseResponder).send(
                message=AttestedResrouceWitnessResponse(
                    state=WitnessingState.ATTESTED.value,
                    document=attested_resource,
                    witness_proof=witnessed_resource.get("proof")[-1],
                    request_id=request_id,
                ),
                connection_id=connection_id,
            )

        return {"status": "success", "message": "Witness successful."}

    async def create_invitation(self, alias=None, label=None, multi_use=False) -> str:
        """Create a witness invitation."""
        witness_key = await self.get_witness_key()
        try:
            invi_rec = await OutOfBandManager(self.profile).create_invitation(
                hs_protos=[
                    HSProto.get("https://didcomm.org/didexchange/1.0"),
                    HSProto.get("https://didcomm.org/didexchange/1.1"),
                ],
                alias=alias,
                my_label=label,
                goal_code="witness-service",
                goal=f"did:key:{witness_key}",
                multi_use=multi_use,
            )
            return invi_rec.serialize()
        except OutOfBandManagerError as e:
            raise WitnessError(e)
