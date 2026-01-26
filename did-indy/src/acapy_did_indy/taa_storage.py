"""Storage implementation for TAA acceptances."""

import json
import logging
from typing import List, Optional

from acapy_agent.core.profile import Profile, ProfileSession
from acapy_agent.storage.base import BaseStorage
from acapy_agent.storage.error import StorageError, StorageNotFoundError
from acapy_agent.storage.record import StorageRecord

from .models.taa_acceptance import TAAAcceptance, TAAAcceptanceSchema

LOGGER = logging.getLogger(__name__)

TAA_ACCEPTANCE_RECORD_TYPE = "did_indy_taa_acceptance"


async def save_taa_acceptance(profile: Profile, taa_acceptance: TAAAcceptance) -> None:
    """Save a TAA acceptance record.

    Args:
        profile: The profile to save the record to
        taa_acceptance: The TAA acceptance to save
    """
    schema = TAAAcceptanceSchema()
    record_value = schema.dump(taa_acceptance)
    record_id = f"{taa_acceptance.namespace}:{taa_acceptance.version}"

    async with profile.session() as session:
        storage = session.inject(BaseStorage)
        LOGGER.debug(
            f"Saving TAA acceptance with ID {record_id} and in storage: {str(storage)}"
        )
        try:
            await storage.add_record(
                StorageRecord(
                    type=TAA_ACCEPTANCE_RECORD_TYPE,
                    id=record_id,
                    value=json.dumps(record_value),
                    tags={
                        "namespace": taa_acceptance.namespace,
                        "version": taa_acceptance.version,
                        "digest": taa_acceptance.digest,
                    },
                )
            )
        except StorageError:
            # Record already exists
            await storage.update_record(
                StorageRecord(
                    type=TAA_ACCEPTANCE_RECORD_TYPE,
                    id=record_id,
                    value=json.dumps(record_value),
                    tags={
                        "namespace": taa_acceptance.namespace,
                        "version": taa_acceptance.version,
                        "digest": taa_acceptance.digest,
                    },
                ),
                json.dumps(record_value),
                {
                    "namespace": taa_acceptance.namespace,
                    "version": taa_acceptance.version,
                    "digest": taa_acceptance.digest,
                },
            )


async def get_taa_acceptance(
    session: ProfileSession, namespace: str, version: Optional[str] = None
) -> Optional[TAAAcceptance]:
    """Get a TAA acceptance record.

    Args:
        profile: The profile to get the record from
        namespace: The namespace to get the TAA acceptance for
        version: The version to get the TAA acceptance for

    Returns:
        The TAA acceptance record, or None if not found
    """
    query = {}
    # query = {"namespace": namespace}
    if version:
        query["version"] = version

    try:
        storage = session.inject(BaseStorage)
        records = await storage.find_all_records(TAA_ACCEPTANCE_RECORD_TYPE, query)
        LOGGER.debug(
            "Found %d TAA acceptance records for namespace '%s'",
            len(records),
            namespace,
        )
        LOGGER.debug("TAA acceptance records: %s", records)
        if not records:
            return None

        # Return the most recent record if no version specified
        record = records[0]  # Get first record if multiple
        value = json.loads(record.value)
        loaded = TAAAcceptanceSchema().load(value)
        if isinstance(loaded, TAAAcceptance):
            return loaded
        return None
    except StorageNotFoundError:
        return None
    except StorageError as err:
        LOGGER.error("Error retrieving TAA acceptance: %s", err)
        return None


async def get_all_taa_acceptances(profile: Profile) -> List[TAAAcceptance]:
    """Get all TAA acceptance records.

    Args:
        profile: The profile to get the records from

    Returns:
        A list of TAA acceptance records
    """
    async with profile.session() as session:
        storage = session.inject(BaseStorage)

        try:
            records = await storage.find_all_records(TAA_ACCEPTANCE_RECORD_TYPE, {})
        except StorageNotFoundError:
            return []
        except StorageError as err:
            LOGGER.error("Error retrieving TAA acceptances: %s", err)
            return []
    result = []
    for record in records:
        value = json.loads(record.value)
        loaded = TAAAcceptanceSchema().load(value)
        if isinstance(loaded, TAAAcceptance):
            result.append(loaded)
    return result
