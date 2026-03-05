"""MsoIssuer helper class to issue a mso."""

from typing import Union
import logging
from datetime import datetime, timedelta, timezone
import random
import hashlib
import os
import cbor2
from pycose.headers import Algorithm, KID
from pycose.keys import CoseKey
from pycose.messages import Sign1Message

LOGGER = logging.getLogger(__name__)
DIGEST_SALT_LENGTH = 32
CBORTAGS_ATTR_MAP = {"birth_date": 1004, "expiry_date": 1004, "issue_date": 1004}


def shuffle_dict(d: dict):
    """Shuffle a dictionary."""
    keys = list(d.keys())
    for i in range(random.randint(3, 27)):  # nosec: B311
        random.shuffle(keys)
    return {key: d[key] for key in keys}


class MsoIssuer:
    """MsoIssuer helper class to issue a mso."""

    def __init__(
        self,
        data: dict,
        private_key: CoseKey,
        x509_cert: str,
        digest_alg: str = "SHA-256",
    ):
        """Constructor."""

        self.data: dict = data
        self.hash_map: dict = {}
        self.disclosure_map: dict = {}
        self.digest_alg: str = digest_alg
        self.private_key: CoseKey = private_key
        self.x509_cert = x509_cert

        hashfunc = getattr(hashlib, "sha256" if digest_alg == "SHA-256" else digest_alg)

        digest_cnt = 0
        for ns, values in data.items():
            if not isinstance(values, dict):
                continue
            self.disclosure_map[ns] = {}
            self.hash_map[ns] = {}

            for k, v in shuffle_dict(values).items():
                _rnd_salt = os.urandom(32)
                _value_cbortag = CBORTAGS_ATTR_MAP.get(k, None)

                if _value_cbortag:
                    v = cbor2.CBORTag(_value_cbortag, v)

                self.disclosure_map[ns][digest_cnt] = {
                    "digestID": digest_cnt,
                    "random": _rnd_salt,
                    "elementIdentifier": k,
                    "elementValue": v,
                }
                self.hash_map[ns][digest_cnt] = hashfunc(
                    cbor2.dumps(
                        cbor2.CBORTag(
                            24, cbor2.dumps(self.disclosure_map[ns][digest_cnt])
                        )
                    )
                ).digest()

                digest_cnt += 1

    def format_datetime_repr(self, dt: datetime) -> str:
        """Format a datetime object to a string representation."""
        return dt.isoformat().split(".")[0] + "Z"

    def sign(
        self,
        device_key: Union[dict, None] = None,
        valid_from: Union[None, datetime] = None,
        doctype: str = None,
    ) -> Sign1Message:
        """Sign a mso and returns it in Sign1Message type."""
        if device_key is None:
            raise ValueError("device_key is required")

        utcnow = datetime.now(timezone.utc)
        exp = utcnow + timedelta(hours=(24 * 365))

        if getattr(device_key, "y", None) is not None:
            device_key_dict = {
                1: 2,  # kty: EC2
                3: -7,  # alg: ECDSA (ES256)
                -1: 1,  # crv: P-256
                -2: device_key.x,
                -3: device_key.y,
            }
        else:
            device_key_dict = {
                1: 1,  # kty: OKP
                3: -8,  # alg: EdDSA
                -1: 6,  # crv: Ed25519
                -2: device_key.x,
            }

        payload = {
            "version": "1.0",
            "digestAlgorithm": self.digest_alg,
            "valueDigests": self.hash_map,
            "deviceKeyInfo": {"deviceKey": device_key_dict},
            "docType": doctype or list(self.hash_map)[0],
            "validityInfo": {
                "signed": cbor2.CBORTag(0, self.format_datetime_repr(utcnow)),
                "validFrom": cbor2.CBORTag(
                    0, self.format_datetime_repr(valid_from or utcnow)
                ),
                "validUntil": cbor2.CBORTag(0, self.format_datetime_repr(exp)),
            },
        }

        tagged_payload_bytes = cbor2.dumps(cbor2.CBORTag(24, cbor2.dumps(payload)))

        mso = Sign1Message(
            phdr={
                Algorithm: self.private_key.alg,
                KID: self.private_key.kid,
                # 33: self.x509_cert,
            },
            # TODO: x509 (cbor2.CBORTag(33)) and federation trust_chain support
            # (cbor2.CBORTag(27?)) here
            # 33 means x509chain standing to rfc9360
            # in both protected and unprotected for interop purpose .. for now.
            uhdr={33: self.x509_cert},
            payload=tagged_payload_bytes,
        )
        mso.key = (
            self.private_key
        )  # signed in mdoc issuer - see https://share.google/aimode/XiHFf55UJByrdpvqN

        return mso
