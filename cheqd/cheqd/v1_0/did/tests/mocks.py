from unittest.mock import AsyncMock


def setup_mock_registrar(mock_registrar, generate_did_doc_response, create_responses):
    mock_registrar.generate_did_doc = AsyncMock(return_value=generate_did_doc_response)
    mock_registrar.create = AsyncMock()
    mock_registrar.create.side_effect = iter(create_responses)


registrar_generate_did_doc_response = {
    "didDoc": {
        "id": "did:cheqd:testnet:123456",
        "verificationMethod": {"publicKey": "someVerificationKey"},
    }
}

registrar_create_responses = [
    {
        "jobId": "MOCK_ID",
        "didState": {
            "state": "action",
            "signingRequest": [{"kid": "MOCK_KID", "serializedPayload": "MOCK"}],
        },
    },
    {
        "jobId": "MOCK_ID",
        "didState": {"state": "finished", "didDocument": {"MOCK_KEY": "MOCK_VALUE"}},
    },
]

registrar_create_responses_no_signing_request = [
    {
        "jobId": "MOCK_ID",
        "didState": {
            "state": "action",
            "signingRequest": [],
        },
    },
]
registrar_create_responses_network_fail = [
    {
        "jobId": "MOCK_ID",
        "didState": {
            "state": "error",
            "reason": "Network failure",
        },
    },
]
