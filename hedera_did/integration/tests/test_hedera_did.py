import re
from typing import Match

class TestHederaDid:
    def test_hedera_did_register(self, holder, Something):
        hedera_method = "hedera"
        key_type = "ed25519"
        key_type_capitalized = key_type.capitalize()

        holder.create_wallet(persist_token=True)

        resp = holder.register_did(
                key_type=key_type_capitalized
                )

        assert resp == {
                "key_type": key_type,
                "verkey": Something,
                "did": Something
                }

        did = resp["did"]

        verkey_match: Match[str] | None = re.search(
                r'did:hedera:testnet:([^_]+)',
                did
                )
        assert verkey_match is not None
        verkey_from_did = verkey_match.group(1)
        verkey_from_did_no_multibase = verkey_from_did[1:]

        verkey = resp["verkey"]

        assert verkey == verkey_from_did_no_multibase

        resp= holder.get_wallet_did(
                method=hedera_method, 
                did=did
                )

        assert resp == {
                "results": [
                      {
                        "did": did,
                        "verkey": verkey,
                        "posture": "wallet_only",
                        "key_type": key_type,
                        "method": hedera_method,
                        "metadata": {}
                      }
                    ]
                }
