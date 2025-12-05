"""Parameter Resolver for resolving DID creation parameters."""

import logging
from typing import Optional

from acapy_agent.core.profile import Profile

from ..config.config import get_witnesses
from .key_chain import KeyChainManager

LOGGER = logging.getLogger(__name__)

WEBVH_METHOD = "did:webvh:1.0"


class ParameterResolver:
    """Resolves and builds DID creation parameters.

    Parameters are resolved from user options, defaults, and policies.
    """

    def __init__(self, profile: Profile):
        """Initialize the ParameterResolver with a profile."""
        self.profile = profile
        self.key_chain = KeyChainManager(profile)

    def apply_defaults(self, options: dict, defaults: dict) -> dict:
        """Apply default parameter options if not overwritten by request.

        Args:
            options: The user provided did creation options
            defaults: The default configured options

        Returns:
            Options dict with defaults applied
        """
        resolved_options = options.copy()

        resolved_options["portability"] = resolved_options.get(
            "portability", defaults.get("portability", False)
        )
        resolved_options["prerotation"] = resolved_options.get(
            "prerotation", defaults.get("prerotation", False)
        )
        # Support both camelCase and snake_case for backward compatibility
        witness_threshold = resolved_options.get(
            "witnessThreshold"
        ) or resolved_options.get(
            "witness_threshold", defaults.get("witness_threshold", 0)
        )
        resolved_options["witness_threshold"] = witness_threshold
        resolved_options["watchers"] = resolved_options.get(
            "watchers", defaults.get("watchers", None)
        )

        return resolved_options

    def apply_policy(self, server_parameters: dict, options: dict) -> dict:
        """Apply server policy to did creation options.

        Args:
            server_parameters: The parameters object returned by the server,
                based on the configured policies
            options: The user provided did creation options

        Returns:
            Options dict with policy applied
        """
        resolved_options = options.copy()

        # Apply witness threshold from policy
        if server_parameters.get("witness", {}).get("threshold", 0):
            resolved_options["witness_threshold"] = server_parameters.get("witness").get(
                "threshold"
            )

        # Apply watchers from policy
        if server_parameters.get("watchers", None):
            resolved_options["watchers"] = server_parameters.get("watchers")

        # Apply portability from policy
        if server_parameters.get("portability", False):
            resolved_options["portability"] = server_parameters.get("portability")

        # Apply prerotation from policy (if nextKeyHashes is empty list,
        # require prerotation)
        if server_parameters.get("nextKeyHashes", None) == []:
            resolved_options["prerotation"] = True

        return resolved_options

    async def build_parameters(self, placeholder_id: str, options: dict) -> dict:
        """Build the parameters dict for DID creation.

        Args:
            placeholder_id: The placeholder DID identifier
            options: Resolved options dict (after defaults and policy)

        Returns:
            Parameters dict ready for DID creation
        """
        parameters = {"method": WEBVH_METHOD}

        # Portability
        # https://identity.foundation/didwebvh/next/#did-portability
        if options.get("portability", False):
            parameters["portable"] = True

        # Witness
        # https://identity.foundation/didwebvh/next/#did-witnesses
        # Support both camelCase and snake_case for backward compatibility
        witness_threshold = options.get("witnessThreshold") or options.get(
            "witness_threshold", 0
        )
        if witness_threshold:
            parameters["witness"] = {
                "threshold": witness_threshold,
                "witnesses": [
                    {"id": witness} for witness in await get_witnesses(self.profile)
                ],
            }

        # Watchers
        # https://identity.foundation/didwebvh/next/#did-watchers
        if options.get("watchers", []):
            parameters["watchers"] = options.get("watchers")

        # Provision Update Key
        # https://identity.foundation/didwebvh/next/#authorized-keys
        update_key = await self.key_chain.create_key(f"{placeholder_id}#updateKey")
        parameters["updateKeys"] = [update_key]

        # Provision Rotation Key
        # https://identity.foundation/didwebvh/next/#pre-rotation-key-hash-generation-and-verification
        if options.get("prerotation", False):
            next_key = await self.key_chain.create_key(f"{placeholder_id}#nextKey")
            parameters["nextKeyHashes"] = [self.key_chain.key_hash(next_key)]

        return parameters

    async def resolve(
        self,
        user_options: dict,
        config_defaults: dict,
        server_parameters: Optional[dict] = None,
        apply_policy: bool = False,
    ) -> tuple[dict, dict]:
        """Resolve parameters in one unified pass.

        This method:
        1. Applies config defaults to user options
        2. Optionally applies server policy
        3. Builds the final parameters dict

        Args:
            user_options: User-provided DID creation options
            config_defaults: Default options from configuration
            server_parameters: Optional server policy parameters
            apply_policy: Whether to apply server policy

        Returns:
            Tuple of (resolved_options, parameters_dict)
            Note: parameters_dict requires placeholder_id, so it's None here.
            Use build_parameters() after getting placeholder_id.
        """
        # Step 1: Apply defaults
        resolved_options = self.apply_defaults(user_options, config_defaults)

        # Step 2: Apply policy if requested
        if apply_policy and server_parameters:
            resolved_options = self.apply_policy(server_parameters, resolved_options)

        return resolved_options, None

    async def resolve_and_build(
        self,
        placeholder_id: str,
        user_options: dict,
        config_defaults: dict,
        server_parameters: Optional[dict] = None,
        apply_policy: bool = False,
    ) -> tuple[dict, dict]:
        """Resolve parameters and build parameters dict in one call.

        This is a convenience method that combines resolve() and build_parameters().

        Args:
            placeholder_id: The placeholder DID identifier
            user_options: User-provided DID creation options
            config_defaults: Default options from configuration
            server_parameters: Optional server policy parameters
            apply_policy: Whether to apply server policy

        Returns:
            Tuple of (resolved_options, parameters_dict)
        """
        # Resolve options
        resolved_options, _ = await self.resolve(
            user_options, config_defaults, server_parameters, apply_policy
        )

        # Build parameters
        parameters = await self.build_parameters(placeholder_id, resolved_options)

        return resolved_options, parameters
