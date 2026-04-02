"""DID utilities for OID4VC."""

import json

from acapy_agent.askar.profile import AskarProfileSession
from acapy_agent.core.profile import ProfileSession
from acapy_agent.storage.base import BaseStorage, StorageRecord
from acapy_agent.storage.error import StorageNotFoundError
from acapy_agent.wallet.base import BaseWallet
from acapy_agent.wallet.did_info import DIDInfo
from acapy_agent.wallet.key_type import ED25519
from acapy_agent.wallet.util import bytes_to_b64
from aries_askar import Key, KeyAlg

from .jwk import DID_JWK


async def _retrieve_default_did(session: ProfileSession):
    """Retrieve default DID from storage."""
    storage = session.inject(BaseStorage)
    wallet = session.inject(BaseWallet)
    try:
        record = await storage.get_record(
            record_type="OID4VP.default",
            record_id="OID4VP.default",
        )
        info = json.loads(record.value)
        info.update(record.tags)
        did_info = await wallet.get_local_did(record.tags["did"])

        return did_info
    except StorageNotFoundError:
        return None


async def _create_default_did(session: ProfileSession) -> DIDInfo:
    """Create default did:jwk using direct Askar key operations.

    Mirrors the approach used by the /did/jwk/create admin route so that
    the resulting DID is stored exactly the same way and can be resolved
    by jwt_sign / key_material_for_kid.
    """
    assert isinstance(session, AskarProfileSession), (
        "did_utils requires an Askar-backed profile session"
    )

    wallet = session.inject(BaseWallet)
    storage = session.inject(BaseStorage)

    key = Key.generate(KeyAlg.ED25519)
    await session.handle.insert_key(key.get_jwk_thumbprint(), key)

    jwk = json.loads(key.get_jwk_public())
    jwk["use"] = "sig"
    did = "did:jwk:" + bytes_to_b64(json.dumps(jwk).encode(), urlsafe=True, pad=False)

    did_info = DIDInfo(
        did=did,
        verkey=key.get_jwk_thumbprint(),
        metadata={},
        method=DID_JWK,
        key_type=ED25519,
    )
    await wallet.store_did(did_info)

    record = StorageRecord(
        type="OID4VP.default",
        value=json.dumps({"verkey": did_info.verkey, "metadata": did_info.metadata}),
        tags={"did": did_info.did},
        id="OID4VP.default",
    )
    await storage.add_record(record)

    return did_info


async def retrieve_or_create_did_jwk(
    session: ProfileSession, key_type=ED25519
) -> DIDInfo:
    """Retrieve existing did:jwk or create a new one."""
    key = await _retrieve_default_did(session)
    if key:
        return key

    return await _create_default_did(session)
