import re
from typing import Match


class TestHederaDid:
    def test_hedera_did_register(self, holder, Something):
        hedera_method = "hedera"
        key_type = "ed25519"
        key_type_capitalized = key_type.capitalize()

        holder.create_wallet(persist_token=True)

        resp = holder.register_did(key_type=key_type_capitalized)

        assert resp == {"key_type": key_type, "verkey": Something, "did": Something}

        did = resp["did"]

        verkey_match: Match[str] | None = re.search(r"did:hedera:testnet:([^_]+)", did)
        assert verkey_match is not None
        verkey_from_did = verkey_match.group(1)
        verkey_from_did_no_multibase = verkey_from_did[1:]

        verkey = resp["verkey"]

        assert verkey == verkey_from_did_no_multibase

        resp = holder.get_wallet_did(method=hedera_method, did=did)

        assert resp == {
            "results": [
                {
                    "did": did,
                    "verkey": verkey,
                    "posture": "wallet_only",
                    "key_type": key_type,
                    "method": hedera_method,
                    "metadata": {},
                }
            ]
        }

    def test_hedera_did_resolve(self, holder, Something):
        method = "hedera:testnet"
        ver_key = "zHNJ37tiLbGxD7XPvnTkaZCAV3PCe5P4HJFGMGUkVVZAJ"
        ver_key_no_multibase = ver_key[1:]
        topic_id = "0.0.5254574"
        did = f"did:{method}:{ver_key}_{topic_id}"

        holder.create_wallet(persist_token=True)

        response = holder.resolve_did(did)

        assert response == {
            "did_document": {
                "didDocumentMetadata": {
                    "versionId": "1734001354.326603",
                    "created": "2024-12-12",
                    "updated": "2024-12-12",
                },
                "didResolutionMetadata": {"contentType": "application/did+ld+json"},
                "didDocument": {
                    "@context": "https://www.w3.org/ns/did/v1",
                    "id": did,
                    "verificationMethod": [
                        {
                            "id": f"{did}#did-root-key",
                            "type": "Ed25519VerificationKey2018",
                            "controller": did,
                            "publicKeyBase58": ver_key_no_multibase,
                        }
                    ],
                    "assertionMethod": [f"{did}#did-root-key"],
                    "authentication": [f"{did}#did-root-key"],
                },
            },
            "metadata": {
                "resolver_type": "native",
                "resolver": "HederaDIDResolver",
                "retrieved_time": Something,
                "duration": Something,
            },
        }
