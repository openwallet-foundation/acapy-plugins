"""High-level flow helpers for OID4VC integration tests.

These helpers encapsulate common multi-step workflows to reduce boilerplate.
"""

import asyncio
import uuid
from typing import Any

from .constants import (
    ALGORITHMS,
    VALIDATION_MAX_ATTEMPTS,
    VALIDATION_POLL_INTERVAL,
    CredentialFormat,
    Doctype,
)


class CredentialFlowHelper:
    """Helper for credential issuance flows."""

    def __init__(
        self,
        issuer_admin,
        holder_client,
    ):
        """Initialize with admin controller and holder client.

        Args:
            issuer_admin: ACA-Py issuer admin controller
            holder_client: HTTP client for holder (Credo/Sphereon)
        """
        self.issuer_admin = issuer_admin
        self.holder_client = holder_client

    async def issue_sd_jwt(
        self,
        *,
        vct: str,
        claims_config: dict[str, Any],
        credential_subject: dict[str, Any],
        sd_list: list[str],
        issuer_did: str,
        holder_did_method: str = "key",
        credential_id: str | None = None,
    ) -> dict[str, Any]:
        """Issue an SD-JWT credential through complete flow.

        Args:
            vct: Verifiable Credential Type URI
            claims_config: Claims configuration for the credential
            credential_subject: Actual claim values
            sd_list: List of claim paths for selective disclosure
            issuer_did: Issuer DID (with verification method)
            holder_did_method: Holder DID method (default: "key")
            credential_id: Optional credential ID (generated if not provided)

        Returns:
            Dict with credential, exchange_id, config_id, issuer_did
        """
        # Generate unique ID
        if not credential_id:
            credential_id = f"SDJWTCred_{uuid.uuid4().hex[:8]}"

        # Create credential configuration
        credential_config = {
            "id": credential_id,
            "format": CredentialFormat.SD_JWT.value,
            "cryptographic_binding_methods_supported": ["did:key", "jwk"],
            "credential_signing_alg_values_supported": ALGORITHMS.SD_JWT_ALGS,
            "proof_types_supported": {
                "jwt": {"proof_signing_alg_values_supported": ALGORITHMS.SD_JWT_ALGS}
            },
            "format_data": {
                "vct": vct,
                "claims": claims_config,
            },
            "vc_additional_data": {"sd_list": sd_list},
        }

        config_response = await self.issuer_admin.post(
            "/oid4vci/credential-supported/create", json=credential_config
        )
        config_id = config_response["supported_cred_id"]

        # Create exchange
        exchange_request = {
            "supported_cred_id": config_id,
            "credential_subject": credential_subject,
            "did": issuer_did,
        }

        exchange_response = await self.issuer_admin.post(
            "/oid4vci/exchange/create", json=exchange_request
        )
        exchange_id = exchange_response["exchange_id"]

        # Get credential offer
        offer_response = await self.issuer_admin.get(
            "/oid4vci/credential-offer", params={"exchange_id": exchange_id}
        )
        credential_offer_uri = offer_response["credential_offer"]

        # Holder accepts offer
        accept_request = {
            "credential_offer": credential_offer_uri,
            "holder_did_method": holder_did_method,
        }

        credential_response = await self.holder_client.post(
            "/oid4vci/accept-offer", json=accept_request
        )
        assert credential_response.status_code == 200, (
            f"Credential issuance failed: {credential_response.text}"
        )

        credential_result = credential_response.json()
        credential = self._extract_credential(credential_result)

        return {
            "credential": credential,
            "exchange_id": exchange_id,
            "config_id": config_id,
            "issuer_did": issuer_did,
            "credential_offer_uri": credential_offer_uri,
        }

    async def issue_jwt_vc(
        self,
        *,
        vc_type: list[str],
        context: list[str],
        credential_subject: dict[str, Any],
        issuer_did: str,
        holder_did_method: str = "key",
        credential_id: str | None = None,
    ) -> dict[str, Any]:
        """Issue a JWT VC credential through complete flow.

        Args:
            vc_type: VC types (e.g., ["VerifiableCredential", "UniversityDegree"])
            context: JSON-LD contexts
            credential_subject: Actual claim values
            issuer_did: Issuer DID (with verification method)
            holder_did_method: Holder DID method (default: "key")
            credential_id: Optional credential ID (generated if not provided)

        Returns:
            Dict with credential, exchange_id, config_id, issuer_did
        """
        # Generate unique ID
        if not credential_id:
            credential_id = f"JWTVCCred_{uuid.uuid4().hex[:8]}"

        # Create credential configuration
        credential_config = {
            "id": credential_id,
            "format": CredentialFormat.JWT_VC.value,
            "cryptographic_binding_methods_supported": ["did"],
            "credential_signing_alg_values_supported": ALGORITHMS.JWT_VC_ALGS,
            "proof_types_supported": {
                "jwt": {"proof_signing_alg_values_supported": ALGORITHMS.JWT_VC_ALGS}
            },
            "@context": context,
            "type": vc_type,
        }

        config_response = await self.issuer_admin.post(
            "/oid4vci/credential-supported/create", json=credential_config
        )
        config_id = config_response["supported_cred_id"]

        # Create exchange
        exchange_request = {
            "supported_cred_id": config_id,
            "credential_subject": credential_subject,
            "verification_method": issuer_did + "#0",
        }

        exchange_response = await self.issuer_admin.post(
            "/oid4vci/exchange/create", json=exchange_request
        )
        exchange_id = exchange_response["exchange_id"]

        # Get credential offer
        offer_response = await self.issuer_admin.get(
            "/oid4vci/credential-offer", params={"exchange_id": exchange_id}
        )
        credential_offer_uri = offer_response["credential_offer"]

        # Holder accepts offer
        accept_request = {
            "credential_offer": credential_offer_uri,
            "holder_did_method": holder_did_method,
        }

        credential_response = await self.holder_client.post(
            "/oid4vci/accept-offer", json=accept_request
        )
        assert credential_response.status_code == 200, (
            f"Credential issuance failed: {credential_response.text}"
        )

        credential_result = credential_response.json()
        credential = self._extract_credential(credential_result)

        return {
            "credential": credential,
            "exchange_id": exchange_id,
            "config_id": config_id,
            "issuer_did": issuer_did,
            "credential_offer_uri": credential_offer_uri,
        }

    async def issue_mdoc(
        self,
        *,
        doctype: str,
        claims_config: dict[str, Any],
        credential_subject: dict[str, Any],
        issuer_did: str,
        holder_did_method: str = "key",
        credential_id: str | None = None,
    ) -> dict[str, Any]:
        """Issue an mDOC credential through complete flow.

        Args:
            doctype: Document type (e.g., "org.iso.18013.5.1.mDL")
            claims_config: Claims configuration for the credential
            credential_subject: Actual claim values
            issuer_did: Issuer DID (with verification method)
            holder_did_method: Holder DID method (default: "key")
            credential_id: Optional credential ID (generated if not provided)

        Returns:
            Dict with credential, exchange_id, config_id, issuer_did
        """
        # Generate unique ID
        if not credential_id:
            credential_id = f"mDOC_{uuid.uuid4().hex[:8]}"

        # Create credential configuration
        vc_additional_data: dict[str, Any] = {}

        credential_config = {
            "id": credential_id,
            "format": CredentialFormat.MDOC.value,
            "doctype": doctype,
            "cryptographic_binding_methods_supported": ["cose_key", "did:key", "did"],
            "credential_signing_alg_values_supported": ALGORITHMS.MDOC_ALGS,
            "proof_types_supported": {
                "jwt": {"proof_signing_alg_values_supported": ALGORITHMS.MDOC_ALGS}
            },
            "format_data": {
                "doctype": doctype,
                "claims": claims_config,
            },
            "vc_additional_data": vc_additional_data,
        }

        config_response = await self.issuer_admin.post(
            "/oid4vci/credential-supported/create", json=credential_config
        )
        config_id = config_response["supported_cred_id"]

        # Create exchange
        exchange_request = {
            "supported_cred_id": config_id,
            "credential_subject": credential_subject,
            "did": issuer_did,
        }

        exchange_response = await self.issuer_admin.post(
            "/oid4vci/exchange/create", json=exchange_request
        )
        exchange_id = exchange_response["exchange_id"]

        # Get credential offer
        offer_response = await self.issuer_admin.get(
            "/oid4vci/credential-offer", params={"exchange_id": exchange_id}
        )
        credential_offer_uri = offer_response["credential_offer"]

        # Holder accepts offer
        accept_request = {
            "credential_offer": credential_offer_uri,
            "holder_did_method": holder_did_method,
        }

        credential_response = await self.holder_client.post(
            "/oid4vci/accept-offer", json=accept_request
        )
        assert credential_response.status_code == 200, (
            f"Credential issuance failed: {credential_response.text}"
        )

        credential_result = credential_response.json()
        credential = self._extract_credential(credential_result)

        return {
            "credential": credential,
            "exchange_id": exchange_id,
            "config_id": config_id,
            "issuer_did": issuer_did,
            "credential_offer_uri": credential_offer_uri,
        }

    def _extract_credential(self, credential_result: dict) -> str:
        """Extract credential from various response formats."""
        if "credential" in credential_result:
            return credential_result["credential"]
        elif "credentials" in credential_result and credential_result["credentials"]:
            return credential_result["credentials"][0]
        elif "w3c_credential" in credential_result:
            return credential_result["w3c_credential"]
        else:
            raise ValueError(
                f"Cannot find credential in response: {credential_result.keys()}"
            )


class PresentationFlowHelper:
    """Helper for presentation verification flows."""

    def __init__(self, verifier_admin, holder_client):
        """Initialize with verifier admin and holder client.

        Args:
            verifier_admin: ACA-Py verifier admin controller
            holder_client: HTTP client for holder (Credo/Sphereon)
        """
        self.verifier_admin = verifier_admin
        self.holder_client = holder_client

    async def verify_sd_jwt(
        self,
        *,
        credential: str,
        vct: str,
        required_claims: list[str],
    ) -> dict[str, Any]:
        """Verify an SD-JWT credential through complete flow.

        Args:
            credential: The SD-JWT credential to verify
            vct: Expected VCT value
            required_claims: List of claim paths to request

        Returns:
            Dict with presentation result and matched_credentials
        """
        # Create presentation definition
        presentation_definition = {
            "id": str(uuid.uuid4()),
            "format": {"vc+sd-jwt": {"sd-jwt_alg_values": ALGORITHMS.SD_JWT_ALGS}},
            "input_descriptors": [
                {
                    "id": str(uuid.uuid4()),
                    "format": {
                        "vc+sd-jwt": {"sd-jwt_alg_values": ALGORITHMS.SD_JWT_ALGS}
                    },
                    "constraints": {
                        "fields": [
                            {
                                "path": ["$.vct"],
                                "filter": {"type": "string", "const": vct},
                            },
                            *[{"path": [f"$.{claim}"]} for claim in required_claims],
                        ]
                    },
                }
            ],
        }

        pres_def_response = await self.verifier_admin.post(
            "/oid4vp/presentation-definition",
            json={"pres_def": presentation_definition},
        )
        pres_def_id = pres_def_response["pres_def_id"]

        # Create presentation request
        presentation_request = await self.verifier_admin.post(
            "/oid4vp/request",
            json={
                "pres_def_id": pres_def_id,
                "vp_formats": {
                    "vc+sd-jwt": {"sd-jwt_alg_values": ALGORITHMS.SD_JWT_ALGS}
                },
            },
        )
        request_uri = presentation_request["request_uri"]
        presentation_id = presentation_request["presentation"]["presentation_id"]

        # Holder presents credential
        present_request = {"request_uri": request_uri, "credentials": [credential]}
        presentation_response = await self.holder_client.post(
            "/oid4vp/present", json=present_request
        )

        assert presentation_response.status_code == 200, (
            f"Presentation failed: {presentation_response.text}"
        )

        # Wait for validation
        validated_presentation = await self.wait_for_validation(presentation_id)

        return {
            "presentation_id": presentation_id,
            "pres_def_id": pres_def_id,
            "request_uri": request_uri,
            "presentation": validated_presentation,
            "matched_credentials": validated_presentation.get(
                "matched_credentials", {}
            ),
        }

    async def verify_mdoc(
        self,
        *,
        credential: str,
        doctype: str,
        required_claims: list[str],
        namespace: str = Doctype.MDL_NAMESPACE,
    ) -> dict[str, Any]:
        """Verify an mDOC credential through complete flow.

        Args:
            credential: The mDOC credential to verify
            doctype: Expected doctype
            required_claims: List of claim names to request
            namespace: Namespace for claims (default: MDL namespace)

        Returns:
            Dict with presentation result and matched_credentials
        """
        # Create presentation definition
        # NOTE: The input descriptor id MUST be the doctype string (e.g.,
        # "org.iso.18013.5.1.mDL"). Credo's createPresentationDefinitionDeviceResponse
        # matches input descriptors to mdoc documents by filtering
        # `inputDescriptor.id === document.docType`.
        # All fields MUST include `intent_to_retain` (Credo's assertMdocInputDescriptor
        # enforces this strictly - it throws if any field lacks the property).
        presentation_definition = {
            "id": str(uuid.uuid4()),
            "format": {"mso_mdoc": {"alg": ALGORITHMS.MDOC_ALGS}},
            "input_descriptors": [
                {
                    "id": doctype,
                    "format": {"mso_mdoc": {"alg": ALGORITHMS.MDOC_ALGS}},
                    "constraints": {
                        # limit_disclosure: required is mandatory for mDOC presentations;
                        # Credo's MdocDeviceResponse.assertMdocInputDescriptor enforces it.
                        "limit_disclosure": "required",
                        "fields": [
                            {
                                "path": [f"$['{namespace}']['{claim}']"],
                                "intent_to_retain": False,
                            }
                            for claim in required_claims
                        ],
                    },
                }
            ],
        }

        pres_def_response = await self.verifier_admin.post(
            "/oid4vp/presentation-definition",
            json={"pres_def": presentation_definition},
        )
        pres_def_id = pres_def_response["pres_def_id"]

        # Create presentation request
        presentation_request = await self.verifier_admin.post(
            "/oid4vp/request",
            json={
                "pres_def_id": pres_def_id,
                "vp_formats": {"mso_mdoc": {"alg": ALGORITHMS.MDOC_ALGS}},
            },
        )
        request_uri = presentation_request["request_uri"]
        presentation_id = presentation_request["presentation"]["presentation_id"]

        # Holder presents credential
        present_request = {"request_uri": request_uri, "credentials": [credential]}
        presentation_response = await self.holder_client.post(
            "/oid4vp/present", json=present_request
        )

        assert presentation_response.status_code == 200, (
            f"Presentation failed: {presentation_response.text}"
        )

        # Wait for validation
        validated_presentation = await self.wait_for_validation(presentation_id)

        return {
            "presentation_id": presentation_id,
            "pres_def_id": pres_def_id,
            "request_uri": request_uri,
            "presentation": validated_presentation,
            "matched_credentials": validated_presentation.get(
                "matched_credentials", {}
            ),
        }

    async def verify_dcql(
        self,
        *,
        credential: str,
        dcql_query: dict[str, Any],
    ) -> dict[str, Any]:
        """Verify credential using DCQL query.

        Args:
            credential: The credential to verify
            dcql_query: DCQL query definition

        Returns:
            Dict with presentation result and matched_credentials
        """
        # Create DCQL query
        dcql_response = await self.verifier_admin.post(
            "/oid4vp/dcql/queries", json=dcql_query
        )
        dcql_query_id = dcql_response["dcql_query_id"]

        # Create presentation request
        presentation_request = await self.verifier_admin.post(
            "/oid4vp/dcql/request",
            json={"dcql_query_id": dcql_query_id},
        )
        request_uri = presentation_request["request_uri"]
        presentation_id = presentation_request["presentation"]["presentation_id"]

        # Holder presents credential
        present_request = {"request_uri": request_uri, "credentials": [credential]}
        presentation_response = await self.holder_client.post(
            "/oid4vp/present", json=present_request
        )

        assert presentation_response.status_code == 200, (
            f"Presentation failed: {presentation_response.text}"
        )

        # Wait for validation
        validated_presentation = await self.wait_for_validation(presentation_id)

        return {
            "presentation_id": presentation_id,
            "dcql_query_id": dcql_query_id,
            "request_uri": request_uri,
            "presentation": validated_presentation,
            "matched_credentials": validated_presentation.get(
                "matched_credentials", {}
            ),
        }

    async def wait_for_validation(
        self,
        presentation_id: str,
        max_attempts: int = VALIDATION_MAX_ATTEMPTS,
        poll_interval: float = VALIDATION_POLL_INTERVAL,
    ) -> dict[str, Any]:
        """Poll for presentation validation completion.

        Args:
            presentation_id: Presentation ID to poll
            max_attempts: Maximum number of polling attempts
            poll_interval: Seconds between polling attempts

        Returns:
            Validated presentation record

        Raises:
            TimeoutError: If validation doesn't complete within max_attempts
        """
        for attempt in range(max_attempts):
            presentation = await self.verifier_admin.get(
                f"/oid4vp/presentation/{presentation_id}"
            )

            if (
                presentation.get("verified") == "true"
                or presentation.get("verified") is True
            ):
                return presentation

            state = presentation.get("state")
            if state == "abandoned":
                raise RuntimeError(
                    f"Presentation abandoned: {presentation.get('error', 'Unknown error')}"
                )
            if state == "presentation-invalid":
                errors = presentation.get("errors", [])
                raise AssertionError(
                    f"Presentation verification failed (presentation-invalid). "
                    f"Errors: {errors}"
                )

            await asyncio.sleep(poll_interval)

        raise TimeoutError(
            f"Presentation validation timed out after {max_attempts} attempts "
            f"({max_attempts * poll_interval}s)"
        )
