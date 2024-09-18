"""Issue an SD-JWT credential."""

from copy import deepcopy
from dataclasses import dataclass
import logging
from aries_cloudagent.core.profile import Profile
from pydid import DIDUrl
from sd_jwt.issuer import SDJWTIssuer, SDObj
import time
import re
from jsonpointer import JsonPointer, EndOfList, JsonPointerException
from typing import Any, Dict, List, Optional

from aries_cloudagent.admin.request_context import AdminRequestContext
from oid4vc.cred_processor import CredProcessor, CredIssueError
from oid4vc.jwt import jwt_sign
from oid4vc.models.exchange import OID4VCIExchangeRecord
from oid4vc.models.supported_cred import SupportedCredential
from oid4vc.pop_result import PopResult


LOGGER = logging.getLogger(__name__)


# Certain claims, if present, are never to be included in the selective disclosures list.

# For flat claims, it's a simple matter of preventing the basic JSON pointer:
FLAT_CLAIMS_NEVER_SD = ("/iss", "/exp", "/vct", "/nbf")

# For claims that are objects, we need to be sure that neither the full claim, nor any
# sub-element of the object, is included in the selective disclosure, while still allowing
# claims with similar names to be selectively disclosable

# e.g., this regex will match `/status` or `/status/foo`, but not `/statuses`,
# in case `statuses` is a valid item to include in disclosures
OBJ_CLAIMS_NEVER_SD = re.compile(r"(?:/cnf|/status)(?:/.+)*")


class SDJWTError(BaseException):
    """SD-JWT Error."""


@dataclass
class ClaimMetadata:
    """Claim metadata."""

    mandatory: bool = False
    value_type: Optional[str] = None
    display: Optional[dict] = None


class SdJwtCredIssueProcessor(CredProcessor):
    """Credential processor class for sd_jwt_vc format."""

    format = "vc+sd-jwt"

    async def issue_cred(
        self,
        body: Any,
        supported: SupportedCredential,
        ex_record: OID4VCIExchangeRecord,
        pop: PopResult,
        context: AdminRequestContext,
    ) -> Any:
        """Return a signed credential in SD-JWT format."""
        assert supported.format_data
        assert supported.vc_additional_data

        sd_list = supported.vc_additional_data.get("sd_list", [])
        assert isinstance(sd_list, list)

        if body.get("vct") != supported.format_data.get("vct"):
            raise CredIssueError("Requested vct does not match offer.")

        current_time = int(time.time())
        claims = deepcopy(ex_record.credential_subject)

        if pop.holder_kid and pop.holder_kid.startswith("did:"):
            claims["sub"] = DIDUrl(pop.holder_kid).did
        elif pop.holder_jwk:
            claims["cnf"] = {"jwk": pop.holder_jwk}
        else:
            raise ValueError("Unsupported pop holder value")

        claims = {
            **claims,
            "vct": supported.format_data["vct"],
            "iss": ex_record.issuer_id,
            "iat": current_time,
        }

        headers = {
            "kid": ex_record.verification_method,
            "typ": "vc+sd-jwt",
        }

        profile = context.profile
        did = ex_record.issuer_id
        ver_method = ex_record.verification_method
        try:
            return await sd_jwt_sign(sd_list, claims, headers, profile, did, ver_method)
        except SDJWTError as error:
            raise CredIssueError("Could not sign SD-JWT VC") from error

    def validate_credential_subject(
        self, supported: SupportedCredential, subject: dict
    ):
        """Validate the credential subject."""
        vc_additional = supported.vc_additional_data
        assert vc_additional
        assert supported.format_data
        claims_metadata = supported.format_data.get("claims")
        sd_list = vc_additional.get("sd_list", [])

        # TODO this will only enforce mandatory fields that are selectively disclosable
        # We should validate that disclosed claims that are mandatory are also present
        missing = []
        for sd in sd_list:
            # iat is the only claim that can be disclosable that is not set in the subject
            if sd == "/iat":
                continue
            pointer = JsonPointer(sd)

            metadata = pointer.resolve(claims_metadata)
            if metadata:
                metadata = ClaimMetadata(**metadata)
            else:
                metadata = ClaimMetadata()

            claim = pointer.resolve(subject, Unset)
            if claim is Unset and metadata.mandatory:
                missing.append(pointer.path)

            # TODO type checking against value_type

        if missing:
            raise CredIssueError(
                "Invalid credential subject; selectively discloseable claim is"
                f" mandatory but missing: {missing}"
            )

    def validate_supported_credential(self, supported: SupportedCredential):
        """Validate a supported SD JWT VC Credential."""

        format_data = supported.format_data
        vc_additional = supported.vc_additional_data
        if not format_data:
            raise ValueError("SD-JWT VC needs format_data")
        if not format_data.get("vct"):
            raise ValueError('SD-JWT VC needs format_data["vct"]')
        if not vc_additional:
            raise ValueError("SD-JWT VC needs vc_additional_data")

        sd_list = vc_additional.get("sd_list", [])

        bad_claims = []
        for sd in sd_list:
            if (
                sd in FLAT_CLAIMS_NEVER_SD
                or OBJ_CLAIMS_NEVER_SD.fullmatch(sd)
                or sd == ""
                or sd[-1] == "/"
            ):
                bad_claims.append(sd)

        if bad_claims:
            raise SDJWTError(
                "The following claims cannot be"
                f"included in the selective disclosures: {bad_claims}"
                "\nThese values are protected and cannot be selectively disclosable:"
                f"{', '.join(FLAT_CLAIMS_NEVER_SD)}, /cnf, /status"
                "\nOr, you provided an empty string, or a string that ends with a `/`"
                "which are invalid for this purpose."
            )

        bad_pointer = []
        for sd in sd_list:
            try:
                JsonPointer(sd)
            except JsonPointerException:
                bad_pointer.append(sd)

        if bad_pointer:
            raise ValueError(f"Invalid JSON pointer(s): {bad_pointer}")


class SDJWTIssuerACAPy(SDJWTIssuer):
    """SDJWTIssuer class for ACA-Py implementation."""

    def __init__(
        self,
        user_claims: dict,
        issuer_key,
        holder_key,
        profile: Profile,
        headers: dict,
        did: Optional[str] = None,
        verification_method: Optional[str] = None,
        add_decoy_claims: bool = False,
        serialization_format: str = "compact",
    ):
        """Initialize an SDJWTIssuerACAPy instance."""
        self._user_claims = user_claims
        self._issuer_key = issuer_key
        self._holder_key = holder_key

        self.profile = profile
        self.headers = headers
        self.did = did
        self.verification_method = verification_method

        self._add_decoy_claims = add_decoy_claims
        self._serialization_format = serialization_format
        self.ii_disclosures = []

    async def _create_signed_jws(self):
        self.serialized_sd_jwt = await jwt_sign(
            self.profile,
            self.headers,
            self.sd_jwt_payload,
            self.did,
            self.verification_method,
        )

    async def issue(self) -> str:
        """Issue an sd-jwt."""
        self._check_for_sd_claim(self._user_claims)
        self._assemble_sd_jwt_payload()
        await self._create_signed_jws()
        self._create_combined()
        return self.sd_jwt_issuance


Unset = object()


async def sd_jwt_sign(
    sd_list: List[str],
    claims: Dict[str, Any],
    headers: Dict[str, Any],
    profile: Profile,
    did: Optional[str] = None,
    verification_method: Optional[str] = None,
):
    """Compose and sign an sd-jwt."""

    for sd in sd_list:
        sd_pointer = JsonPointer(sd)
        sd_claim = sd_pointer.resolve(claims, Unset)

        if sd_claim is Unset:
            raise SDJWTError(f"Claim for {sd_pointer.path} not found in payload.")

        sub, key = sd_pointer.to_last(claims)

        if isinstance(sub, EndOfList):
            raise SDJWTError("Invalid JSON Pointer; EndOfList referenced")

        if isinstance(sub, dict):
            sub[SDObj(key)] = sd_claim
            sub.pop(key)

        if isinstance(sub, list):
            sd_pointer.set(claims, SDObj(sd_claim))

    return await SDJWTIssuerACAPy(
        user_claims=claims,
        issuer_key=None,
        holder_key=None,
        profile=profile,
        headers=headers,
        did=did,
        verification_method=verification_method,
    ).issue()
