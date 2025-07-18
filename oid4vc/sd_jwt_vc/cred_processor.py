"""Issue an SD-JWT credential."""

import json
import logging
import re
import time
from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Union

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.core.profile import Profile
from acapy_agent.wallet.jwt import JWTVerifyResult
from acapy_agent.wallet.util import bytes_to_b64
from jsonpointer import EndOfList, JsonPointer, JsonPointerException
from pydid import DIDUrl
from sd_jwt.issuer import SDJWTIssuer, SDObj
from sd_jwt.verifier import KB_DIGEST_KEY, SDJWTVerifier

from oid4vc.cred_processor import (
    CredProcessorError,
    CredVerifier,
    Issuer,
    PresVerifier,
    VerifyResult,
)
from oid4vc.config import Config
from oid4vc.jwt import jwt_sign, jwt_verify
from oid4vc.models.exchange import OID4VCIExchangeRecord
from oid4vc.models.presentation import OID4VPPresentation
from oid4vc.models.supported_cred import SupportedCredential
from oid4vc.pop_result import PopResult
from oid4vc.status_handler import StatusHandler

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


class SdJwtCredIssueProcessor(Issuer, CredVerifier, PresVerifier):
    """Credential processor class for sd_jwt_vc format."""

    async def issue(
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

        sd_list = supported.vc_additional_data.get("sd_list") or []
        assert isinstance(sd_list, list)

        if body.get("vct") != supported.format_data.get("vct"):
            raise CredProcessorError("Requested vct does not match offer.")

        current_time = int(time.time())
        claims = deepcopy(ex_record.credential_subject)

        if pop.holder_kid and pop.holder_kid.startswith("did:"):
            claims["sub"] = DIDUrl(pop.holder_kid).did
            claims["cnf"] = {"kid": pop.holder_kid}
        elif pop.holder_jwk:
            # FIXME: Credo explicitly requires a `kid` in `cnf`,
            # so we're making credo happy here
            pop.holder_jwk["use"] = "sig"
            did = "did:jwk:" + bytes_to_b64(
                json.dumps(pop.holder_jwk).encode(), urlsafe=True, pad=False
            )

            claims["cnf"] = {"kid": did + "#0", "jwk": pop.holder_jwk}
        else:
            raise ValueError("Unsupported pop holder value")

        headers = {
            "kid": ex_record.verification_method,
            "typ": "vc+sd-jwt",
        }

        claims = {
            **claims,
            "vct": supported.format_data["vct"],
            "iss": ex_record.issuer_id,
            "iat": current_time,
        }

        status_handler = context.inject_or(StatusHandler)
        if status_handler and (
            credential_status := await status_handler.assign_status_entries(
                context, supported.supported_cred_id, ex_record.exchange_id
            )
        ):
            claims["status"] = credential_status
            LOGGER.debug("credential with status: %s", claims)

        profile = context.profile
        did = ex_record.issuer_id
        ver_method = ex_record.verification_method
        try:
            cred = await sd_jwt_sign(sd_list, claims, headers, profile, did, ver_method)
            LOGGER.debug("SD JWT VC CREDENTIAL: %s", cred)
            return cred
        except SDJWTError as error:
            raise CredProcessorError("Could not sign SD-JWT VC") from error

    def validate_credential_subject(self, supported: SupportedCredential, subject: dict):
        """Validate the credential subject."""
        vc_additional = supported.vc_additional_data
        assert vc_additional
        assert supported.format_data
        claims_metadata = supported.format_data.get("claims")
        sd_list = vc_additional.get("sd_list") or []

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
            raise CredProcessorError(
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

        sd_list = vc_additional.get("sd_list") or []

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
                "The following claims cannot be "
                f"included in the selective disclosures: {bad_claims} "
                "\nThese values are protected and cannot be selectively disclosable: "
                f"{', '.join(FLAT_CLAIMS_NEVER_SD)}, /cnf, /status "
                "\nOr, you provided an empty string, or a string that ends with a `/` "
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

    async def verify_presentation(
        self,
        profile: Profile,
        presentation: Any,
        presentation_record: OID4VPPresentation,
    ) -> VerifyResult:
        """Verify signature over credential or presentation."""
        context: AdminRequestContext = profile.context
        config = Config.from_settings(context.settings)

        result = await sd_jwt_verify(
            profile, presentation, config.endpoint, presentation_record.nonce
        )
        # TODO: This is a little hacky
        return VerifyResult(result.verified, presentation)

    async def verify_credential(
        self,
        profile: Profile,
        credential: Any,
    ) -> VerifyResult:
        """Verify signature over credential."""
        # TODO: Can we optimize this? since we end up doing this twice in a row

        result = await sd_jwt_verify(profile, credential)
        return VerifyResult(result.verified, result.payload)


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


class SDJWTVerifyResult(JWTVerifyResult):
    """Result from verifying SD-JWT."""

    class Meta:
        """SDJWTVerifyResult metadata."""

        schema_class = "SDJWTVerifyResultSchema"

    def __init__(
        self,
        headers,
        payload,
        valid,
        kid,
        disclosures,
    ):
        """Initialize an SDJWTVerifyResult instance."""
        super().__init__(
            headers,
            payload,
            valid,
            kid,
        )
        self.disclosures = disclosures


class SDJWTVerifierACAPy(SDJWTVerifier):
    """SDJWTVerifier class for ACA-Py implementation."""

    def __init__(
        self,
        profile: Profile,
        sd_jwt_presentation: str,
        expected_aud: Union[str, None] = None,
        expected_nonce: Union[str, None] = None,
        serialization_format: str = "compact",
    ):
        """Initialize an SDJWTVerifierACAPy instance."""
        self.profile = profile
        self.sd_jwt_presentation = sd_jwt_presentation

        if serialization_format not in ("compact", "json"):
            raise ValueError(f"Unknown serialization format: {serialization_format}")
        self._serialization_format = serialization_format

        self.expected_aud = expected_aud
        self.expected_nonce = expected_nonce

    async def _verify_sd_jwt(self):
        verified = await jwt_verify(
            self.profile,
            self._unverified_input_sd_jwt,
        )
        if verified.verified is False:
            raise CredProcessorError("Invalid signature")

        self._sd_jwt_payload = verified.payload
        self._holder_public_key_payload = self._sd_jwt_payload.get("cnf", None)

    async def verify(self):
        """Verify an sd-jwt."""
        self._parse_sd_jwt(self.sd_jwt_presentation)
        self._create_hash_mappings(self._input_disclosures)
        await self._verify_sd_jwt()

        if self.expected_aud or self.expected_nonce:
            if not (self.expected_aud and self.expected_nonce):
                raise ValueError(
                    "Either both expected_aud and expected_nonce must be provided "
                    "or both must be None"
                )
            await self._verify_key_binding_jwt(
                self.expected_aud,
                self.expected_nonce,
            )

        return self

    async def _verify_key_binding_jwt(
        self,
        expected_aud: Union[str, None] = None,
        expected_nonce: Union[str, None] = None,
    ):
        # Verify the key binding JWT using the holder public key
        if not self._holder_public_key_payload:
            raise ValueError("No holder public key in SD-JWT")
        verified_kb_jwt = await jwt_verify(
            self.profile, self._unverified_input_key_binding_jwt
        )

        if verified_kb_jwt.headers["typ"] != self.KB_JWT_TYP_HEADER:
            raise ValueError("Invalid header typ")
        if verified_kb_jwt.payload["aud"] != expected_aud:
            raise ValueError("Invalid audience")
        if verified_kb_jwt.payload["nonce"] != expected_nonce:
            raise ValueError("Invalid nonce")

        if self._serialization_format == "compact":
            string_to_hash = self._combine(
                self._unverified_input_sd_jwt, *self._input_disclosures, ""
            )
            expected_sd_jwt_presentation_hash = self._b64hash(
                string_to_hash.encode("ascii")
            )

            if (
                verified_kb_jwt.payload[KB_DIGEST_KEY]
                != expected_sd_jwt_presentation_hash
            ):
                raise ValueError("Invalid digest in KB-JWT")


async def sd_jwt_verify(
    profile: Profile,
    sd_jwt_presentation: str,
    expected_aud: Optional[str] = None,
    expected_nonce: Optional[str] = None,
) -> VerifyResult:
    """Verify sd-jwt using SDJWTVerifierACAPy.verify()."""
    sd_jwt_verifier = SDJWTVerifierACAPy(
        profile, sd_jwt_presentation, expected_aud, expected_nonce
    )
    try:
        payload = (await sd_jwt_verifier.verify()).get_verified_payload()
        return VerifyResult(True, payload)
    except Exception:
        return VerifyResult(False, None)
