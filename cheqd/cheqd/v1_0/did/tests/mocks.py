from unittest.mock import AsyncMock

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

registrar_responses_no_signing_request = [
    {
        "jobId": "MOCK_ID",
        "didState": {
            "state": "action",
            "signingRequest": [],
        },
        "resourceState": {
            "state": "action",
            "signingRequest": [],
        },
    },
]

registrar_responses_network_fail = [
    {
        "jobId": "MOCK_ID",
        "didState": {
            "state": "error",
            "reason": "Network failure",
        },
        "resourceState": {
            "state": "error",
            "reason": "Network failure",
        },
    },
]

registrar_responses_not_finished = [
    {
        "jobId": "MOCK_ID",
        "didState": {
            "state": "action",
            "signingRequest": [{"kid": "MOCK_KID", "serializedPayload": "MOCK"}],
        },
        "resourceState": {
            "state": "action",
            "signingRequest": [{"kid": "MOCK_KID", "serializedPayload": "MOCK"}],
        },
    },
    {
        "jobId": "MOCK_ID",
        "didState": {
            "state": "error",
            "description": "Not finished",
            "reason": "Not finished",
        },
        "resourceState": {
            "state": "error",
            "description": "Not finished",
            "reason": "Not finished",
        },
    },
]

registrar_update_responses = [
    {
        "jobId": "MOCK_ID",
        "didState": {
            "state": "action",
            "signingRequest": [{"kid": "MOCK_KID", "serializedPayload": "MOCK"}],
        },
    },
    {
        "jobId": "MOCK_ID",
        "didState": {
            "state": "finished",
            "didDocument": {"MOCK_KEY": "MOCK_VALUE_UPDATED"},
        },
    },
]

registrar_deactivate_responses = [
    {
        "jobId": "MOCK_ID",
        "didState": {
            "state": "action",
            "signingRequest": [{"kid": "MOCK_KID", "serializedPayload": "MOCK"}],
        },
    },
    {
        "jobId": "MOCK_ID",
        "didState": {
            "state": "finished",
            "didDocument": {"MOCK_KEY": "MOCK_VALUE_DEACTIVATED"},
        },
    },
]

registrar_create_resource_responses = [
    {
        "jobId": "MOCK_ID",
        "resourceState": {
            "state": "action",
            "signingRequest": [{"kid": "MOCK_KID", "serializedPayload": "MOCK"}],
        },
    },
    {
        "jobId": "MOCK_ID",
        "resourceState": {
            "state": "finished",
            "didDocument": {"MOCK_KEY": "MOCK_VALUE"},
        },
    },
]


def setup_mock_registrar(
    mock_registrar,
    generate_did_doc_response=registrar_generate_did_doc_response,
    create_responses=registrar_create_responses,
    update_responses=registrar_update_responses,
    deactivate_responses=registrar_deactivate_responses,
    create_resource_responses=registrar_create_resource_responses,
):
    mock_registrar.generate_did_doc = AsyncMock(return_value=generate_did_doc_response)
    mock_registrar.create = AsyncMock()
    mock_registrar.create.side_effect = iter(create_responses)
    mock_registrar.update = AsyncMock()
    mock_registrar.update.side_effect = iter(update_responses)
    mock_registrar.deactivate = AsyncMock()
    mock_registrar.deactivate.side_effect = iter(deactivate_responses)
    mock_registrar.create_resource = AsyncMock()
    mock_registrar.create_resource.side_effect = iter(create_resource_responses)


def setup_mock_resolver(mock_resolver, response={"MOCK_KEY": "MOCK_VALUE"}):
    mock_resolver.resolve = AsyncMock(return_value=response)
