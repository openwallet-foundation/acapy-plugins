"""Endorser utilities."""

import logging

from acapy_agent.connections.models.conn_record import ConnRecord
from acapy_agent.core.profile import Profile
from acapy_agent.protocols.out_of_band.v1_0.manager import OutOfBandManager
from acapy_agent.protocols.out_of_band.v1_0.messages.invitation import InvitationMessage

from .manager import TransactionManager
from .transaction_jobs import TransactionJob


def is_author_role(profile: Profile):
    """Check if agent is running in author mode."""
    return profile.settings.get_value("endorser.author")


async def get_endorser_connection_id(profile: Profile):
    """Determine default endorser connection for author."""
    if not is_author_role(profile):
        return None

    endorser_alias = profile.settings.get_value("endorser.endorser_alias")
    if not endorser_alias:
        return None
    try:
        async with profile.session() as session:
            connection_records = await ConnRecord.retrieve_by_alias(
                session, endorser_alias
            )
            connection_id = connection_records[0].connection_id
            return connection_id
    except Exception:
        return None


"""Common endorsement utilities."""


LOGGER = logging.getLogger(__name__)


class EndorsementSetupError(Exception):
    """Endorsement setup error."""


async def attempt_auto_author_with_endorser_setup(profile: Profile):
    """Automatically setup the author's endorser connection if possible."""
    if not is_author_role(profile):
        return

    endorser_alias = profile.settings.get_value("endorser.endorser_alias")
    if not endorser_alias:
        LOGGER.info("No endorser alias, alias is required if invitation is specified.")
        return

    connection_id = await get_endorser_connection_id(profile)
    if connection_id:
        LOGGER.info("Connected to endorser from previous connection.")
        return

    endorser_did = profile.settings.get_value("endorser.endorser_public_did")
    if not endorser_did:
        LOGGER.info("No endorser DID, can connect, but can't setup connection metadata.")
        return

    endorser_invitation = profile.settings.get_value("endorser.endorser_invitation")
    if not endorser_invitation:
        LOGGER.info("No endorser invitation, can't create connection automatically.")
        return

    try:
        # OK, we are an author, we have no endorser connection but we have enough info
        # to automatically initiate the connection
        invite = InvitationMessage.from_url(endorser_invitation)
        if invite:
            oob_mgr = OutOfBandManager(profile)
            oob_record = await oob_mgr.receive_invitation(
                invitation=invite,
                auto_accept=True,
                alias=endorser_alias,
            )
            async with profile.session() as session:
                conn_record = await ConnRecord.retrieve_by_id(
                    session, oob_record.connection_id
                )
        else:
            raise EndorsementSetupError("Invalid OOB Invitation URL")

        # configure the connection role and info (don't need to wait for the connection)
        transaction_mgr = TransactionManager(profile)
        await transaction_mgr.set_transaction_my_job(
            record=conn_record,
            transaction_my_job=TransactionJob.TRANSACTION_AUTHOR.name,
        )

        async with profile.session() as session:
            value = await conn_record.metadata_get(session, "endorser_info")
            if value:
                value["endorser_did"] = endorser_did
                value["endorser_name"] = endorser_alias
            else:
                value = {"endorser_did": endorser_did, "endorser_name": endorser_alias}
            await conn_record.metadata_set(session, key="endorser_info", value=value)

        LOGGER.info(
            "Successfully connected to endorser from invitation, and setup connection metadata."  # noqa: E501
        )

    except Exception:
        LOGGER.info("Error accepting endorser invitation/configuring endorser connection")
