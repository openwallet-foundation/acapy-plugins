TEST_DOMAIN = "example.com"
TEST_SCID = "123"
TEST_RECORD = {
    "versionId": "1-Q",
    "parameters": {"scid": TEST_SCID},
    "state": {"id": f"did:webvh:{TEST_SCID}:{TEST_DOMAIN}"},
    "proof": {"type": "DataIntegrityProof"},
}
