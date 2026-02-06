"""Operations supporting mso_mdoc issuance."""

import json
import logging
import os
from binascii import hexlify
from typing import Any, Mapping, Optional

import cbor2
import base64
import json

from acapy_agent.core.profile import Profile
from acapy_agent.wallet.base import BaseWallet
from acapy_agent.wallet.default_verification_key_strategy import (
    BaseVerificationKeyStrategy,
)
from acapy_agent.wallet.util import b64_to_bytes, bytes_to_b64
from pycose.keys import CoseKey
from pydid import DIDUrl

from ..mso import MsoIssuer
from ..x509 import selfsigned_x509cert

LOGGER = logging.getLogger(__name__)


def dict_to_b64(value: Mapping[str, Any]) -> str:
    """Encode a dictionary as a b64 string."""
    return bytes_to_b64(json.dumps(value).encode(), urlsafe=True, pad=False)


def b64_to_dict(value: str) -> Mapping[str, Any]:
    """Decode a dictionary from a b64 encoded value."""
    return json.loads(b64_to_bytes(value, urlsafe=True))


def nym_to_did(value: str) -> str:
    """Return a did from nym if passed value is nym, else return value."""
    return value if value.startswith("did:") else f"did:sov:{value}"


def did_lookup_name(value: str) -> str:
    """Return the value used to lookup a DID in the wallet.

    If value is did:sov, return the unqualified value. Else, return value.
    """
    return value.split(":", 3)[2] if value.startswith("did:sov:") else value

def base64url_decode(input_str):
    padding = '=' * (-len(input_str) % 4)
    LOGGER.debug(f"base64url decoding input: {input_str} with padding: {padding}")
    return base64.urlsafe_b64decode(input_str + padding)

def extract_key_from_jwt(jwt_token):
   # header_b64, payload_b64, _ = jwt_token.split('.')
    key = json.loads(base64url_decode(jwt_token))
    LOGGER.debug(f"extracted key from jwt: {key}") 
  #  payload = json.loads(base64url_decode(payload_b64))
    # The key may be in the header (as 'jwk') or in the payload, depending on your JWT
    return key

async def mso_mdoc_sign(
    profile: Profile,
    headers: Mapping[str, Any],
    payload: Mapping[str, Any],
    did: Optional[str] = None,
    verification_method: Optional[str] = None,
) -> str:
    """Create a signed mso_mdoc given headers, payload, and signing DID or DID URL."""
    if verification_method is None:
        if did is None:
            raise ValueError("did or verificationMethod required.")

        did = nym_to_did(did)

        verkey_strat = profile.inject(BaseVerificationKeyStrategy)
        verification_method = await verkey_strat.get_verification_method_id_for_did(
            did, profile
        )
        if not verification_method:
            raise ValueError("Could not determine verification method from DID")
    else:
        # We look up keys by did for now
        did = DIDUrl.parse(verification_method).did
        if not did:
            raise ValueError("DID URL must be absolute")

    async with profile.session() as session:
        wallet = session.inject(BaseWallet)
        LOGGER.info(f"mso_mdoc sign: {did}")

        did_info = await wallet.get_local_did(did_lookup_name(did))
        key_pair = await wallet._session.handle.fetch_key(did_info.verkey)
        jwk_bytes = key_pair.key.get_jwk_secret()
        jwk = json.loads(jwk_bytes)

    return mdoc_sign(jwk, headers, payload)


def mdoc_sign(jwk: dict, headers: Mapping[str, Any], payload: Mapping[str, Any]) -> str:
    """Create a signed mso_mdoc given headers, payload, and private key."""
    pk_dict = {
        "KTY": 'EC2',  # Quick Hack that needs to be fixed - jwk.get("kty") returns  ....
        "CURVE": 'P_256',  # Quick hack jwk.get("crv") returns ....
        "ALG": "EdDSA" if jwk.get("kty") == "OKP" else "ES256",
        "D": b64_to_bytes(jwk.get("d") or "", True),  # EdDSA
        "X": b64_to_bytes(jwk.get("x") or "", True),  # EdDSA, EcDSA
        "Y": b64_to_bytes(jwk.get("y") or "", True),  # EcDSA
        "KID": os.urandom(32),
    }
    cose_key = CoseKey.from_dict(pk_dict)

    LOGGER.info(f"signing mso_mdoc with headers: {headers}, payload: {payload}")
    if isinstance(headers, dict):
        doctype = headers.get("doctype") or ""
        LOGGER.info(f"doctype from headers: {headers.get("deviceKey")}")
        jwt_header_key = extract_key_from_jwt(headers.get("deviceKey").lstrip('\'"')) #need to fix device_key at source
        device_key_dict = {
            "KTY": "OKP",
            "CURVE": "Ed25519",
            "ALG": "EdDSA",
            "X": b64_to_bytes(jwt_header_key.get("x") or "", True),
        }
        device_key= CoseKey.from_dict(device_key_dict)
       
       # LOGGER.info(f"extracted device_key: {device_key}")
       # device_key = headers.get("deviceKey") or ""
    else:
        raise ValueError("missing headers.")
    
    if isinstance(payload, dict):
        doctype = headers.get("doctype")
        data = [{"doctype": doctype, "data": payload}]
    else:
        raise ValueError("missing payload.")

    documents = []
    for doc in data:
        _cert = selfsigned_x509cert(private_key=cose_key)
        msoi = MsoIssuer(data=doc["data"], private_key=cose_key, x509_cert=_cert)
        mso = msoi.sign(device_key=device_key, doctype=doctype)
        issuer_auth = mso.encode()
        LOGGER.debug(f"issuer_auth signed: {hexlify(issuer_auth)}") 
        issuer_auth = cbor2.loads(issuer_auth).value
        LOGGER.debug(f"issuer_auth before wrapping: {issuer_auth}")
        issuer_auth[2] = cbor2.dumps(cbor2.CBORTag(24, issuer_auth[2]))
       # document = {
        #    "docType": doctype,
        #    "issuerSigned": {
        #        "nameSpaces": {
        #            ns: [cbor2.CBORTag(24, cbor2.dumps(v)) for k, v in dgst.items()]
        #            for ns, dgst in msoi.disclosure_map.items()
        #        },
        #        "issuerAuth": issuer_auth,
        #    },
            # this is required during the presentation.
            #  'deviceSigned': {
            #  # TODO
            #  }
        #}
        #documents.append(document)

    signed = {
    #    "version": "1.0", TODO: move back to the loop above?
         "nameSpaces": {
            ns: [cbor2.CBORTag(24, cbor2.dumps(v)) for k, v in dgst.items()]
                for ns, dgst in msoi.disclosure_map.items()
            },
         "issuerAuth": issuer_auth,
    #    "status": 0,
    }
    LOGGER.info(f"signed mso_mdoc dict: {signed}")
    signed_hex = hexlify(cbor2.dumps(signed))
    LOGGER.info(f"signed mso_mdoc: {signed_hex}")
    return f"{signed_hex}"
