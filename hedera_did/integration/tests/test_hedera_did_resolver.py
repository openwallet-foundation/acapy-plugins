class TestHederaDidResolver:
    def test_resolve(self, holder, Something):
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
                  "updated": "2024-12-12"
                },
                "didResolutionMetadata": {
                  "contentType": "application/did+ld+json"
                },
                "didDocument": {
                  "@context": "https://www.w3.org/ns/did/v1",
                  "id": did,
                  "verificationMethod": [
                    {
                      "id": f"{did}#did-root-key",
                      "type": "Ed25519VerificationKey2018",
                      "controller": did,
                      "publicKeyBase58": ver_key_no_multibase
                    }
                  ],
                  "assertionMethod": [
                    f"{did}#did-root-key"
                  ],
                  "authentication": [
                    f"{did}#did-root-key"
                  ]
                }
              },
          "metadata": {
            "resolver_type": "native",
            "resolver": "HederaDIDResolver",
            "retrieved_time": Something,
            "duration": Something
          }
        }
