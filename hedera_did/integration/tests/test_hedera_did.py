class TestHederaDid:
    def test_hedera_did_register(self, bob, Something):
        response = bob.register_did({"key_type": "Ed25519"})

        assert response.status_code == 200
        assert response.json() == {
                "key_type": "ed25519",
                "verkey": Something,
                "did": Something
                }
