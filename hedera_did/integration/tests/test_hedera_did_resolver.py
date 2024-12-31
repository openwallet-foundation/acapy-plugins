class TestHederaDidResolver:
    def test_resolve(self, bob, Something):
        response = bob.resolve_did("did:hedera:testnet:zHNJ37tiLbGxD7XPvnTkaZCAV3PCe5P4HJFGMGUkVVZAJ_0.0.5254574")

        assert response.status_code == 200
        assert response.json() == {
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
                  "id": "did:hedera:testnet:zHNJ37tiLbGxD7XPvnTkaZCAV3PCe5P4HJFGMGUkVVZAJ_0.0.5254574",
                  "verificationMethod": [
                    {
                      "id": "did:hedera:testnet:zHNJ37tiLbGxD7XPvnTkaZCAV3PCe5P4HJFGMGUkVVZAJ_0.0.5254574#did-root-key",
                      "type": "Ed25519VerificationKey2018",
                      "controller": "did:hedera:testnet:zHNJ37tiLbGxD7XPvnTkaZCAV3PCe5P4HJFGMGUkVVZAJ_0.0.5254574",
                      "publicKeyBase58": "HNJ37tiLbGxD7XPvnTkaZCAV3PCe5P4HJFGMGUkVVZAJ"
                    }
                  ],
                  "assertionMethod": [
                    "did:hedera:testnet:zHNJ37tiLbGxD7XPvnTkaZCAV3PCe5P4HJFGMGUkVVZAJ_0.0.5254574#did-root-key"
                  ],
                  "authentication": [
                    "did:hedera:testnet:zHNJ37tiLbGxD7XPvnTkaZCAV3PCe5P4HJFGMGUkVVZAJ_0.0.5254574#did-root-key"
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
