TEST_DOMAIN = "example.com"
TEST_SCID = "123"
TEST_RECORD_ID = "e0463162-f363-42d1-8710-46bb2d8a53d2"
TEST_RECORD = {
    "versionId": "1-Q",
    "parameters": {"scid": TEST_SCID},
    "state": {"id": f"did:webvh:{TEST_SCID}:{TEST_DOMAIN}"},
    "proof": {"type": "DataIntegrityProof"},
}
