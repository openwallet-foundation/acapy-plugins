"""Status handler."""

import logging
import gzip
import math
import os
import time
import tempfile
from functools import wraps
from typing import Optional
from types import SimpleNamespace
from datetime import datetime, timedelta, timezone
from bitarray import bitarray
from filelock import FileLock, Timeout
from pathlib import Path

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.core.profile import ProfileSession
from acapy_agent.storage.error import StorageNotFoundError
from acapy_agent.wallet.util import bytes_to_b64

from .config import Config
from .error import StatusListError
from .models import StatusListDef, StatusListShard, StatusListCred, StatusListReg
from .jwt import jwt_sign

LOGGER = logging.getLogger(__name__)


def with_retries(max_attempts=3, delay=2):
    """Decorator to retry a function."""

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(1, max_attempts + 1):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    LOGGER.warning(f"Attempt {attempt} failed with error: {e}")
                    if attempt == max_attempts:
                        raise
                    time.sleep(delay)

        return wrapper

    return decorator


@with_retries(max_attempts=3, delay=2)
def write_to_file(path: str, data: bytes) -> None:
    """Write data to a local file atomically."""

    full_path = Path(path).resolve()
    try:
        full_path.parent.mkdir(parents=True, exist_ok=True)
        LOGGER.debug(f"Writing to local file (atomic): {full_path}")
        lock_path = full_path.with_suffix(full_path.suffix + ".lock")
        with FileLock(str(lock_path), timeout=10):
            with tempfile.NamedTemporaryFile(
                dir=full_path.parent, delete=False
            ) as tmp_file:
                tmp_file.write(data)
                temp_path = Path(tmp_file.name)
            try:
                os.replace(temp_path, full_path)
            except OSError as e:
                LOGGER.error(f"Failed to replace {temp_path} with {full_path}: {e}")
                try:
                    if temp_path.exists():
                        os.unlink(temp_path)
                except OSError:
                    LOGGER.warning(f"Failed to clean up temporary file: {temp_path}")
                raise
        LOGGER.debug("Write to local file completed.")
        # Explicitly remove the lock file (needed on Unix)
        try:
            if lock_path.exists():
                lock_path.unlink()
        except OSError as e:
            LOGGER.warning(f"Failed to remove lock file {lock_path}: {e}")
    except (OSError, Timeout) as e:
        LOGGER.error(f"Failed to write to file {full_path}: {e}")
        try:
            if lock_path.exists():
                lock_path.unlink()
        except OSError as e:
            LOGGER.warning(f"Failed to remove lock file {lock_path}: {e}")
        raise


def get_wallet_id(context: AdminRequestContext):
    """Get wallet id."""

    if hasattr(context, "metadata") and context.metadata:
        return context.metadata.get("wallet_id")
    else:
        return "base"


async def assign_status_list_number(session: ProfileSession, wallet_id: str):
    """Get status list number."""

    try:
        registry = await StatusListReg.retrieve_by_id(session, wallet_id, for_update=True)
        if registry.list_count < 0:
            raise StatusListError("Status list registry has negative list count.")
    except StorageNotFoundError:
        registry = StatusListReg(id=wallet_id, list_count=0, new_with_id=True)

    list_number = registry.list_count
    registry.list_count += 1
    await registry.save(session)

    return str(list_number)


async def create_next_status_list(session: ProfileSession, definition: StatusListDef):
    """Create status list shards."""

    for i in range(math.ceil(definition.list_size / definition.shard_size)):
        shard = StatusListShard(
            definition_id=definition.id,
            list_number=definition.next_list_number,
            shard_number=str(i),
            shard_size=definition.shard_size,
            status_size=definition.status_size,
        )
        await shard.save(session, reason="Create new status list.")


async def generate_random_index(context: AdminRequestContext, definition_id: str):
    """Generate random index."""

    async with context.profile.transaction() as txn:
        # generate a random index
        definition = await StatusListDef.retrieve_by_id(
            txn, definition_id, for_update=True
        )
        random_index, shard_number, shard_index = definition.get_random_entry()

        # increment list index
        definition.list_index += 1
        if definition.list_index >= definition.list_size:
            definition.list_number = definition.next_list_number
            definition.list_index = 0
            definition.seed_list()

        # create a spare list
        if definition.list_number == definition.next_list_number:
            wallet_id = get_wallet_id(context)
            definition.next_list_number = await assign_status_list_number(txn, wallet_id)
            definition.add_list_number(definition.next_list_number)
            await create_next_status_list(txn, definition)

        # save and commit
        await definition.save(txn, reason="Increment list index.")
        await txn.commit()

        return random_index, shard_number, shard_index


async def assign_random_entry(context: AdminRequestContext, definition_id: str):
    """Assign a random status list entry."""

    random_index, shard_number, shard_index = await generate_random_index(
        context, definition_id
    )

    async with context.profile.transaction() as txn:
        definition = await StatusListDef.retrieve_by_id(txn, definition_id)

        tag_filter = {
            "definition_id": definition.id,
            "list_number": definition.list_number,
            "shard_number": str(shard_number),
        }
        # lock shard and assign an entry
        shard = await StatusListShard.retrieve_by_tag_filter(
            txn, tag_filter, for_update=True
        )

        # retun None if entry is assigned
        if not shard.mask_bits[shard_index]:
            LOGGER.error(
                (
                    f"Entry is already assigned at "
                    f"list={definition.list_number}, "
                    f"entry={definition.list_index}, "
                    f"shard={shard_number}, "
                    f"index={shard_index}"
                )
            )
            return None

        # mark entry as assigned
        mask_bits = shard.mask_bits
        mask_bits[shard_index] = False
        shard.mask_bits = mask_bits
        await shard.save(txn, reason="Assign a status entry")

        # commmit all changes
        await txn.commit()

        # return status list entry
        result = {
            "list_number": definition.list_number,
            "list_index": random_index,
            "status": shard.status_bits[
                shard_index : shard_index + definition.status_size
            ].to01(),
            "assigned": not shard.mask_bits[shard_index],
        }
        LOGGER.debug(f"Assigned status list entry: {result}")

        return result


async def assign_status_list_entry(context: AdminRequestContext, definition_id: str):
    """Assign available status list entry."""

    retries = 10
    for i in range(retries):
        if entry := await assign_random_entry(context, definition_id):
            break
        if i >= retries - 1:
            raise StatusListError(
                f"Error in obtaining status list entry after {retries} retries."
            )

    return entry


async def assign_status_entries(
    context: AdminRequestContext,
    supported_cred_id: str,
    credential_id: str,
):
    """Create a credential status."""

    status_list = []
    config = Config.from_settings(context.profile.settings)
    async with context.profile.session() as session:
        definitions = await StatusListDef.query(
            session, {"supported_cred_id": supported_cred_id}
        )
        if not definitions or len(definitions) == 0:
            return None

        for definition in definitions:
            wallet_id = get_wallet_id(context)
            entry = await assign_status_list_entry(context, definition.id)
            entry = SimpleNamespace(**entry)
            public_uri = config.public_uri.format(
                tenant_id=wallet_id,
                list_number=entry.list_number,
            )

            # construct status by status type
            if definition.list_type == "ietf":
                status = {"status_list": {"idx": entry.list_index, "uri": public_uri}}
            else:
                status = {
                    "id": f"{public_uri}#{entry.list_index}",
                    "type": "BitstringStatusListEntry",
                    "statusPurpose": definition.status_purpose,
                    "statusListIndex": entry.list_index,
                    "statusListCredential": public_uri,
                }
                if definition.status_purpose == "message":
                    status["statusSize"] = definition.status_size
                    status["statusMessage"] = definition.status_message

            status_list.append(status)

            # Create status list credential record
            status_list_cred = StatusListCred(
                definition_id=definition.id,
                credential_id=credential_id,
                list_number=entry.list_number,
                list_index=entry.list_index,
            )
            await status_list_cred.save(
                session, reason="Assign a new status list credential entry", event=False
            )

            # Emit event
            payload = status_list_cred.serialize()
            payload["state"] = "assigned"
            payload["status"] = entry.status
            await status_list_cred.emit_event(session, payload)

    if len(status_list) > 1:
        return status_list
    elif len(status_list) == 1:
        return status_list[0]


async def get_status_list_entry(
    session: ProfileSession, definition_id: str, credential_id: str
):
    """Get status list entry."""

    tag_filter = {
        "definition_id": definition_id,
        "credential_id": credential_id,
    }
    record = await StatusListCred.retrieve_by_tag_filter(session, tag_filter)
    list_number = record.list_number
    entry_index = record.list_index

    definition = await StatusListDef.retrieve_by_id(session, definition_id)
    shard_number = entry_index // definition.shard_size
    shard_index = entry_index % definition.shard_size
    tag_filter = {
        "definition_id": definition_id,
        "list_number": str(list_number),
        "shard_number": str(shard_number),
    }
    shard = await StatusListShard.retrieve_by_tag_filter(session, tag_filter)
    bit_index = shard_index * definition.status_size
    return {
        "list": definition.list_number,
        "index": entry_index,
        "status": shard.status_bits[
            bit_index : bit_index + definition.status_size
        ].to01(),
        "assigned": not shard.mask_bits[shard_index],
    }


async def update_status_list_entry(
    session: ProfileSession, definition_id: str, credential_id: str, bitstring: str
):
    """Update status list entry by list number and entry index."""

    tag_filter = {
        "definition_id": definition_id,
        "credential_id": credential_id,
    }
    record = await StatusListCred.retrieve_by_tag_filter(session, tag_filter)
    list_number = record.list_number
    entry_index = record.list_index

    definition = await StatusListDef.retrieve_by_id(session, definition_id)
    shard_number = entry_index // definition.shard_size
    shard_index = entry_index % definition.shard_size
    tag_filter = {
        "definition_id": definition_id,
        "list_number": str(list_number),
        "shard_number": str(shard_number),
    }
    shard = await StatusListShard.retrieve_by_tag_filter(
        session, tag_filter, for_update=True
    )
    bit_index = shard_index * definition.status_size
    status_bits = shard.status_bits
    status_bits[bit_index : bit_index + definition.status_size] = bitarray(bitstring)
    shard.status_bits = status_bits
    await shard.save(session, reason="Update status list entry.")

    # Emit event
    shard.state = "updated"
    payload = shard.serialize()
    payload["credential_id"] = credential_id
    payload["list_index"] = entry_index
    payload["status"] = bitstring
    await shard.emit_event(session, payload)

    return {
        "list": definition.list_number,
        "index": entry_index,
        "status": shard.status_bits[
            bit_index : bit_index + definition.status_size
        ].to01(),
        "assigned": not shard.mask_bits[shard_index],
    }


async def get_status_list(
    context: AdminRequestContext, definition: StatusListDef, list_number: str
):
    """Compress status list."""

    config = Config.from_settings(context.profile.settings)
    wallet_id = get_wallet_id(context)

    async with context.profile.session() as session:
        tag_filter = {"definition_id": definition.id, "list_number": list_number}
        shards = await StatusListShard.query(session, tag_filter)
        shards = sorted(shards, key=lambda s: int(s.shard_number))

        status_bits = bitarray()
        for shard in shards:
            status_bits.extend(shard.status_bits)

        bytes = gzip.compress(status_bits.tobytes())
        base64 = bytes_to_b64(bytes, True)
        encoded_list = base64.rstrip("=")

        public_uri = config.public_uri.format(
            tenant_id=wallet_id,
            list_number=list_number,
        )

        now = datetime.now(timezone.utc)
        validUntil = now + timedelta(days=365)
        unix_now = int(now.timestamp())
        unix_validUntil = int(validUntil.timestamp())
        ttl = 43200

        payload = {
            "iss": definition.issuer_did,
            "nbf": unix_now,
            "jti": f"urn:uuid:{list_number}",
            "sub": public_uri,
        }

        if definition.list_type == "ietf":
            status_list = {
                **payload,
                "iat": unix_now,
                "exp": unix_validUntil,
                "ttl": ttl,
                "status_list": {
                    "bits": definition.status_size,
                    "lst": encoded_list,
                },
            }
        elif definition.list_type == "w3c":
            status_list = {
                **payload,
                "vc": {
                    "@context": ["https://www.w3.org/ns/credentials/v2"],
                    "id": public_uri,
                    "type": [
                        "VerifiableCredential",
                        "BitstringStatusListCredential",
                    ],
                    "issuer": definition.issuer_did,
                    "validFrom": now.isoformat(),
                    "validUntil": validUntil.isoformat(),
                    "credentialSubject": {
                        "id": public_uri + "#list",
                        "type": "BitstringStatusList",
                        "statusPurpose": definition.status_purpose,
                        "encodedList": encoded_list,
                    },
                },
            }
            if definition.status_purpose == "message":
                status_list["vc"]["credentialSubject"]["statusSize"] = (
                    definition.status_size
                )
                status_list["vc"]["credentialSubject"]["statusMessage"] = (
                    definition.status_message
                )
        else:  # raw list
            status_list = {
                "definition_id": definition.id,
                "list_number": list_number,
                "list_size": definition.list_size,
                "status_purpose": definition.status_purpose,
                "status_message": definition.status_message,
                "status_size": definition.status_size,
                "encoded_list": encoded_list,
            }

        return status_list


async def get_status_list_token(
    context: AdminRequestContext,
    list_number: str,
    definition: Optional[StatusListDef] = None,
):
    """Publish status list."""

    if definition is None:
        async with context.profile.session() as session:
            tag_filter = {"list_number": list_number}
            shards = await StatusListShard.query(session, tag_filter, limit=1)
            definition_id = shards[0].definition_id
            definition = await StatusListDef.retrieve_by_id(session, definition_id)

    status_list = await get_status_list(context, definition, list_number)
    headers = {"typ": "statuslist+jwt"} if definition.list_type == "ietf" else {}

    return await jwt_sign(
        profile=context.profile,
        headers=headers,
        payload=status_list,
        did=definition.issuer_did,
        verification_method=definition.verification_method,
    )
