"""Issue an SD-JWT credential."""

from aries_cloudagent.core.profile import Profile
from sd_jwt.issuer import SDJWTIssuer, SDObj
import time
from jsonpointer import JsonPointer
from typing import Any, Dict, List, Mapping, Optional

from aries_cloudagent.admin.request_context import AdminRequestContext
from oid4vc.cred_processor import CredProcessor, CredIssueError
from oid4vc.jwt import jwt_sign
from oid4vc.models.exchange import OID4VCIExchangeRecord
from oid4vc.models.supported_cred import SupportedCredential
from oid4vc.pop_result import PopResult
from oid4vc.public_routes import types_are_subset


class SDJWTError(BaseException):
    """SD-JWT Error."""


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
        if not types_are_subset(body.get("types"), supported.format_data.get("types")):
            raise CredIssueError("Requested types does not match offer.")

        current_time = int(time.time())

        sd_list = supported.vc_additional_data.get("sd_list")
        assert isinstance(sd_list, list)

        claims = {**ex_record.credential_subject}
        headers = {
            "vct": supported.format_data["vct"],
            "iss": ex_record.issuer_id,
            "iat": current_time,
            "kid": ex_record.verification_method,
            # "_sd": [],
        }

        profile = context.inject(Profile)
        return await sd_jwt_sign(sd_list, claims, headers, profile)


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


def sort_sd_list(sd_list) -> List:
    """Sorts sd_list.

    Ensures that selectively disclosable claims deepest
    in the structure are handled first.
    """
    nested_claim_sort = [(len(sd.split(".")), sd) for sd in sd_list]
    nested_claim_sort.sort(reverse=True)
    return [sd[1] for sd in nested_claim_sort]


async def sd_jwt_sign(
    sd_list: List[str],
    claims: Mapping[str, Any],
    headers: Mapping[str, Any],
    profile: Profile,
    did: Optional[str] = None,
    verification_method: Optional[str] = None,
):
    """Compose and sign an sd-jwt."""

    for sd in sd_list:
        sd_pointer = JsonPointer(sd)
        sd_claim = sd_pointer.resolve(claims, None)

        if not sd_claim:
            raise SDJWTError(f"Claim for {sd} not found in payload.")
        else:
            sd_pointer.set(claims, SDObj(sd_claim))
            # for match in matches:
            #     if isinstance(match.context.value, list):
            #         match.context.value.remove(match.value)
            #         match.context.value.append(SDObj(match.value))
            #     else:
            #         match.context.value[SDObj(str(match.path))] = (
            #             match.context.value.pop(str(match.path))
            #         )

    return await SDJWTIssuerACAPy(
        user_claims=claims,
        issuer_key=None,
        holder_key=None,
        profile=profile,
        headers=headers,
        did=did,
        verification_method=verification_method,
    ).issue()
