"""Key Chain Manager for handling all key operations."""

import logging
from typing import Optional

from acapy_agent.core.profile import Profile
from acapy_agent.wallet.keys.manager import MultikeyManager
from multiformats import multibase, multihash

LOGGER = logging.getLogger(__name__)


class KeyChainManager:
    """Manages all key operations including creation, finding, binding, and unbinding."""

    def __init__(self, profile: Profile):
        """Initialize the KeyChainManager with a profile."""
        self.profile = profile

    async def create_key(self, kid: Optional[str] = None) -> str:
        """Create a new key.

        Args:
            kid: Optional key ID to bind the key to

        Returns:
            The multikey string
        """
        async with self.profile.session() as session:
            key = await MultikeyManager(session).create(alg="ed25519", kid=kid)
        return key.get("multikey")

    async def find_key(self, kid: str) -> Optional[str]:
        """Find a key by its key ID.

        Args:
            kid: The key ID to search for

        Returns:
            The multikey string if found, None otherwise
        """
        try:
            async with self.profile.session() as session:
                key = await MultikeyManager(session).from_kid(kid=kid)
            return key.get("multikey")
        except AttributeError:
            return None

    async def get_key(self, kid: str, error_class: type[Exception] = KeyError) -> str:
        """Get a key by its key ID, raising an error if not found.

        Args:
            kid: The key ID to search for
            error_class: Exception class to raise if key not found (default: KeyError)

        Returns:
            The multikey string

        Raises:
            error_class: If the key is not found
        """
        key = await self.find_key(kid)
        if not key:
            raise error_class(f"Key [{kid}] not found.")
        return key

    async def find_multikey(self, multikey: str) -> str:
        """Find a key by its multikey.

        Args:
            multikey: The multikey string to search for

        Returns:
            The multikey string
        """
        async with self.profile.session() as session:
            key = await MultikeyManager(session).from_multikey(multikey)
        return key.get("multikey")

    async def bind_key(self, multikey: str, kid: str) -> str:
        """Bind a key to a given key ID.

        Args:
            multikey: The multikey string to bind
            kid: The key ID to bind to

        Returns:
            The multikey string
        """
        async with self.profile.session() as session:
            key = await MultikeyManager(session).update(kid=kid, multikey=multikey)
        return key.get("multikey")

    async def unbind_key(self, multikey: str, kid: str) -> None:
        """Unbind a key ID from a key.

        Args:
            multikey: The multikey string
            kid: The key ID to unbind
        """
        async with self.profile.session() as session:
            await MultikeyManager(session).unbind_key_id(kid=kid, multikey=multikey)

    def key_hash(self, key: str) -> str:
        """Calculate the hash of a key.

        Args:
            key: The key string to hash

        Returns:
            The base58btc encoded multihash
        """
        return multibase.encode(multihash.digest(key.encode(), "sha2-256"), "base58btc")[
            1:
        ]

    async def update_key(self, did: str) -> Optional[str]:
        """Find the update key for a DID.

        Args:
            did: The DID to get the update key for

        Returns:
            The update key multikey if found, None otherwise
        """
        return await self.find_key(f"{did}#updateKey")

    async def signing_key(self, did: str) -> Optional[str]:
        """Find the signing key for a DID.

        Args:
            did: The DID to get the signing key for

        Returns:
            The signing key multikey if found, None otherwise
        """
        return await self.find_key(f"{did}#signingKey")

    async def next_key(self, did: str) -> Optional[str]:
        """Find the next key for a DID.

        Args:
            did: The DID to get the next key for

        Returns:
            The next key multikey if found, None otherwise
        """
        return await self.find_key(f"{did}#nextKey")

    async def migrate_key(
        self,
        from_did: str,
        to_did: str,
        key_type: str,
    ) -> Optional[str]:
        """Migrate a single key from one DID to another.

        This is useful when transitioning from a placeholder DID to the final DID.

        Args:
            from_did: Source DID to get key from
            to_did: Target DID to bind key to
            key_type: Key type to migrate (e.g., "signingKey", "updateKey", "nextKey")

        Returns:
            The migrated key multikey if found and migrated, None otherwise
        """
        # Use convenience methods for common key types
        if key_type == "signingKey":
            multikey = await self.signing_key(from_did)
        elif key_type == "updateKey":
            multikey = await self.update_key(from_did)
        elif key_type == "nextKey":
            multikey = await self.next_key(from_did)
        else:
            multikey = await self.find_key(f"{from_did}#{key_type}")

        if multikey:
            if key_type == "signingKey":
                # Signing key needs multiple bindings
                await self.bind_key(multikey, f"{to_did}#signingKey")
                await self.bind_key(multikey, f"{to_did}#{multikey}")
            else:
                await self.bind_key(multikey, f"{to_did}#{key_type}")
            return multikey

        return None

    async def rotate_update_key(self, did: str) -> tuple[str, str]:
        """Rotate the update key using the next key.

        This implements the prerotation pattern:
        1. Unbind current update key
        2. Bind next key as new update key
        3. Unbind old next key
        4. Create and bind new next key

        Args:
            did: The DID to rotate keys for

        Returns:
            Tuple of (new_update_key, new_next_key_hash)
        """
        next_key_id = f"{did}#nextKey"
        update_key_id = f"{did}#updateKey"

        # Get existing keys
        previous_next_key = await self.next_key(did)
        previous_update_key = await self.update_key(did)

        # Unbind previous update key
        if previous_update_key:
            await self.unbind_key(previous_update_key, update_key_id)

        # Bind previous next key as new update key
        if previous_next_key:
            await self.bind_key(previous_next_key, update_key_id)

            # Unbind previous next key
            await self.unbind_key(previous_next_key, next_key_id)

        # Create and bind new next key
        next_key = await self.create_key(next_key_id)

        # Get the new update key (which is the previous next key)
        new_update_key = await self.update_key(did)

        return new_update_key, self.key_hash(next_key)

    async def bind_verification_method(
        self, did: str, key_id: str, multikey: str
    ) -> None:
        """Bind a verification method key.

        Args:
            did: The DID
            key_id: The key ID (can be relative like "key1" or full like "did#key1")
            multikey: The multikey to bind
        """
        # Ensure key_id is full format
        if not key_id.startswith(did):
            key_id = f"{did}#{key_id}"

        await self.bind_key(multikey, key_id)

    async def unbind_verification_method(self, did: str, key_id: str) -> None:
        """Unbind a verification method key.

        Args:
            did: The DID
            key_id: The key ID (can be relative like "key1" or full like "did#key1")
        """
        # Ensure key_id is full format
        if not key_id.startswith(did):
            key_id = f"{did}#{key_id}"

        multikey = await self.find_key(key_id)
        if multikey:
            await self.unbind_key(multikey, key_id)
