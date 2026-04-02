"""Digital Credentials Query Language evaluator."""

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from acapy_agent.core.profile import Profile

from oid4vc.cred_processor import CredProcessors
from oid4vc.models.dcql_query import ClaimsQuery, CredentialQuery, DCQLQuery
from oid4vc.models.presentation import OID4VPPresentation

LOGGER = logging.getLogger(__name__)

ClaimsPath = List[str | int | None]
Absent = object()


class ClaimsPathPointer:
    """A pointer into a JSON structure, identifying one or more claims in a VC.

    Example:
    {
        "name": "Arthur Dent",
        "address": {
            "street_address": "42 Market Street",
            "locality": "Milliways",
            "postal_code": "12345"
        },
        "degrees": [
            {
                "type": "Bachelor of Science",
                "university": "University of Betelgeuse"
            },
            {
                "type": "Master of Science",
                "university": "University of Betelgeuse"
            }
        ],
        "nationalities": ["British", "Betelgeusian"]
    }

    The following shows examples of claims path pointers and the respective selected
    claims:
    - ["name"]: The claim name with the value `Arthur Dent` is selected.
    - ["address"]: The claim address with its sub-claims as the value is selected.
    - ["address", "street_address"]: The claim street_address with the value
      `"42 Market Street"` is selected.
    - ["degrees", null, "type"]: All type claims in the degrees array are selected.
    - ["nationalities", 1]: The second nationality is selected.
    """

    def __init__(self, path: ClaimsPath):
        """Init the path pointer."""
        self.path = path

    @staticmethod
    def _str_component(component: str, selected: List[Any], next: List[Any]):
        """Handle a str component."""
        for element in selected:
            if not isinstance(element, dict):
                raise ValueError(
                    "Attempted to step into value by key when value is not an object"
                )
            if component in element:
                next.append(element[component])

    @staticmethod
    def _null_component(selected: List[Any], next: List[Any]):
        """Handle a null component."""
        for element in selected:
            if not isinstance(element, list):
                raise ValueError(
                    "Attempted to select all elements of list but got "
                    "value that is not a list"
                )
            next.extend(element)

    @staticmethod
    def _int_component(component: int, selected: List[Any], next: List[Any]):
        """Handle an int component."""
        for element in selected:
            if not isinstance(element, list):
                raise ValueError(
                    "Attempted to step into value by index when value is not a list"
                )
            if 0 <= component < len(element):
                next.append(element[component])

    def resolve(self, source: Any):
        """Resolve a value from a source object using this path pointer."""
        selected = [source]
        for component in self.path:
            next = []
            if isinstance(component, str):
                self._str_component(component, selected, next)
            elif component is None:
                self._null_component(selected, next)
            elif isinstance(component, int) and component > -1:
                self._int_component(component, selected, next)
            else:
                raise ValueError(
                    f"Invalid type {type(component).__name__} component in path pointer"
                )
            selected = next
        return selected


@dataclass
class DCQLVerifyResult:
    """Result of verification."""

    verified: bool = False
    cred_query_id_to_claims: Dict[str, dict] = field(default_factory=dict)
    details: Optional[str] = None
    satisfied_credential_sets: Optional[List[int]] = (
        None  # Indices of satisfied credential sets
    )


class DCQLQueryEvaluator:
    """Evaluate a query against a submission to ensure it matches."""

    def __init__(self, query: DCQLQuery):
        """Init the evaluator."""
        self.query: DCQLQuery = query

    @classmethod
    def compile(cls, query: dict | DCQLQuery) -> "DCQLQueryEvaluator":
        """Compile an evaluator."""
        if isinstance(query, dict):
            query = DCQLQuery.deserialize(query)

        return cls(query)

    async def _verify_single_credential(
        self,
        profile: Profile,
        cred: CredentialQuery,
        vp_token: Dict[str, Any],
        presentation_record: OID4VPPresentation,
        processors: CredProcessors,
    ) -> Tuple[bool, Optional[str], Optional[dict]]:
        """Verify a single credential from the vp_token.

        Returns:
            Tuple of (success, error_message, verified_payload)
        """
        pres_list = vp_token.get(cred.credential_query_id)
        if not pres_list:
            return (False, f"Missing presentation for {cred.credential_query_id}", None)

        # DCQL vp_token format: {credential_query_id: [presentations...]}
        if isinstance(pres_list, list):
            if len(pres_list) == 0:
                return (
                    False,
                    f"Empty presentation array for {cred.credential_query_id}",
                    None,
                )
            pres = pres_list[0]
        else:
            pres = pres_list

        pres_verifier = processors.pres_verifier_for_format(cred.format)

        vp_result = await pres_verifier.verify_presentation(
            profile=profile,
            presentation=pres,
            presentation_record=presentation_record,
        )
        if not vp_result.verified:
            return (
                False,
                f"Presentation for {cred.credential_query_id} failed verification",
                None,
            )

        cred_verifier = processors.cred_verifier_for_format(cred.format)

        vc_result = await cred_verifier.verify_credential(
            profile=profile,
            credential=vp_result.payload,
        )
        if not vc_result.verified:
            return (
                False,
                f"Credential for {cred.credential_query_id} failed verification",
                None,
            )

        # Credential type validation (doctype for mDOC, vct for SD-JWT, etc.)
        # Uses processor extension point if available, otherwise falls back to
        # hardcoded checks for backward compatibility.
        type_validation_result = self._validate_credential_type(
            cred_verifier, cred, vc_result.payload
        )
        if not type_validation_result[0]:
            return (type_validation_result[0], type_validation_result[1], None)

        # Handle ClaimSets - if defined, at least one claim set must be satisfied
        claims_result = await self._verify_claims(cred, vc_result.payload)
        if not claims_result[0]:
            return claims_result

        return (True, None, vc_result.payload)

    async def _verify_claims(
        self,
        cred: CredentialQuery,
        payload: dict,
    ) -> Tuple[bool, Optional[str], Optional[dict]]:
        """Verify claims for a credential, handling ClaimSets if present.

        Returns:
            Tuple of (success, error_message, payload)
        """
        if not cred.claims:
            return (True, None, payload)

        # Build a map of claim_id -> claim for ClaimSets evaluation
        claim_id_map: Dict[str, ClaimsQuery] = {}
        for claim in cred.claims:
            if claim.id:
                claim_id_map[claim.id] = claim

        # If claim_sets is defined, use it to determine which claims to verify
        if cred.claim_sets:
            # Try each claim set - at least one must be fully satisfied
            for claim_set_idx, claim_set in enumerate(cred.claim_sets):
                all_claims_satisfied = True
                for claim_id in claim_set:
                    claim = claim_id_map.get(claim_id)
                    if not claim:
                        LOGGER.warning(
                            f"ClaimSet references unknown claim id: {claim_id}"
                        )
                        all_claims_satisfied = False
                        break

                    success, _ = self._verify_single_claim(claim, payload)
                    if not success:
                        all_claims_satisfied = False
                        break

                if all_claims_satisfied:
                    LOGGER.debug(f"ClaimSet {claim_set_idx} satisfied")
                    return (True, None, payload)

            return (
                False,
                f"No claim set could be satisfied for {cred.credential_query_id}",
                None,
            )

        # No claim_sets defined - verify all claims individually
        for claim in cred.claims:
            success, error_msg = self._verify_single_claim(claim, payload)
            if not success:
                return (False, error_msg, None)

        return (True, None, payload)

    def _verify_single_claim(
        self,
        claim: ClaimsQuery,
        payload: dict,
    ) -> Tuple[bool, Optional[str]]:
        """Verify a single claim against the payload.

        Returns:
            Tuple of (success, error_message)
        """
        if claim.path is not None:
            # JSON-based claims structure (SD-JWT, etc.) - use path pointer
            pointer = ClaimsPathPointer(claim.path)
            try:
                values = pointer.resolve(payload)
                if not values:
                    return (False, f"Path {claim.path} does not exist")
                if claim.values:
                    # Check if any resolved value matches the required values
                    if not any(v in claim.values for v in values):
                        return (
                            False,
                            (
                                "Credential presented did not match the values "
                                "required by the query"
                            ),
                        )
            except ValueError:
                return (False, f"Path {claim.path} does not exist")

        elif claim.namespace is not None and claim.claim_name is not None:
            # mDOC format - use namespace/claim_name syntax
            namespace_data = payload.get(claim.namespace)
            if namespace_data is None:
                return (
                    False,
                    f"Namespace {claim.namespace} does not exist in credential",
                )
            if claim.claim_name not in namespace_data:
                return (
                    False,
                    (
                        f"Claim {claim.claim_name} does not exist in "
                        f"namespace {claim.namespace}"
                    ),
                )
            value = namespace_data[claim.claim_name]
            if claim.values and value not in claim.values:
                return (
                    False,
                    "Credential presented did not match the values required by the query",
                )

        return (True, None)

    def _validate_credential_type(
        self,
        cred_verifier,
        cred: CredentialQuery,
        payload: dict,
    ) -> Tuple[bool, Optional[str]]:
        """Validate credential type identifier (doctype, vct, etc.).

        Uses processor extension point if available:
        - validate_type_identifier(payload, expected_types) -> Tuple[bool, Optional[str]]

        Falls back to built-in checks for doctype (mDOC) and vct (SD-JWT) if the
        processor doesn't implement the extension.

        Returns:
            Tuple of (success, error_message)
        """
        if not cred.meta:
            return (True, None)

        # Collect expected type identifiers from meta
        expected_types = []
        type_field = None

        if cred.meta.doctype_value:
            expected_types = [cred.meta.doctype_value]
            type_field = "docType"
        elif cred.meta.doctype_values:
            expected_types = cred.meta.doctype_values
            type_field = "docType"
        elif cred.meta.vct_values:
            expected_types = cred.meta.vct_values
            type_field = "vct"

        if not expected_types:
            return (True, None)

        # Use processor extension point if available
        if hasattr(cred_verifier, "validate_type_identifier"):
            return cred_verifier.validate_type_identifier(payload, expected_types)

        # Fallback: built-in validation for known type fields
        if type_field:
            presented_type = payload.get(type_field)
            if presented_type is None:
                return (False, f"Credential is missing {type_field}")
            if presented_type not in expected_types:
                return (
                    False,
                    f"Presented {type_field} '{presented_type}' does not "
                    f"match requested type(s): {expected_types}",
                )

        return (True, None)

    async def _evaluate_credential_sets(
        self,
        verified_cred_ids: Set[str],
    ) -> Tuple[bool, List[int], Optional[str]]:
        """Evaluate credential sets to determine if query is satisfied.

        Returns:
            Tuple of (success, satisfied_set_indices, error_message)
        """
        if not self.query.credential_set:
            # No credential sets defined - all credentials are required
            cred_ids_in_query = {c.credential_query_id for c in self.query.credentials}
            if cred_ids_in_query <= verified_cred_ids:
                return (True, [], None)
            missing = cred_ids_in_query - verified_cred_ids
            return (False, [], f"Missing required credentials: {missing}")

        satisfied_sets = []

        for set_idx, cred_set in enumerate(self.query.credential_set):
            # Each credential_set has 'options' - each option is a list of credential IDs
            # At least one option must be fully satisfied
            is_required = cred_set.required if cred_set.required is not None else True

            option_satisfied = False
            for option in cred_set.options:
                if all(cred_id in verified_cred_ids for cred_id in option):
                    option_satisfied = True
                    break

            if option_satisfied:
                satisfied_sets.append(set_idx)
            elif is_required:
                return (
                    False,
                    satisfied_sets,
                    f"Required credential set {set_idx} not satisfied. "
                    f"Options: {cred_set.options}, Verified: {verified_cred_ids}",
                )

        return (True, satisfied_sets, None)

    async def verify(
        self,
        profile: Profile,
        vp_token: Dict[str, Any],
        presentation_record: OID4VPPresentation,
    ):
        """Verify a submission against the query.

        This method now supports:
        - CredentialSets: Allows specifying alternative combinations of
          credentials
        - ClaimSets: Allows specifying alternative combinations of claims
          within a credential

        The verification process:
        1. Verify each credential in the vp_token against the query
        2. If credential_sets are defined, evaluate which sets are satisfied
        3. Return success if all required credential sets are satisfied
        """
        processors = profile.inject(CredProcessors)
        id_to_claim: Dict[str, dict] = {}
        verified_cred_ids: Set[str] = set()

        # First, verify all credentials that are present in the vp_token
        for cred in self.query.credentials:
            # Check if this credential is present in the submission
            if cred.credential_query_id not in vp_token:
                LOGGER.debug(
                    f"Credential {cred.credential_query_id} not in submission, "
                    "checking if required by credential_sets"
                )
                continue

            success, error_msg, payload = await self._verify_single_credential(
                profile=profile,
                cred=cred,
                vp_token=vp_token,
                presentation_record=presentation_record,
                processors=processors,
            )

            if not success:
                # If credential_sets are defined, this might be optional
                if self.query.credential_set:
                    LOGGER.debug(
                        f"Credential {cred.credential_query_id} failed: {error_msg}, "
                        "but credential_sets defined - continuing"
                    )
                    continue
                # No credential_sets - all credentials are required
                return DCQLVerifyResult(details=error_msg)

            verified_cred_ids.add(cred.credential_query_id)
            id_to_claim[cred.credential_query_id] = payload

        # Evaluate credential sets to determine if query is satisfied
        sets_success, satisfied_sets, sets_error = await self._evaluate_credential_sets(
            verified_cred_ids
        )

        if not sets_success:
            return DCQLVerifyResult(details=sets_error)

        return DCQLVerifyResult(
            verified=True,
            cred_query_id_to_claims=id_to_claim,
            satisfied_credential_sets=satisfied_sets if satisfied_sets else None,
        )
