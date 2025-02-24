from unittest.mock import AsyncMock

from cheqd.cheqd.did.base import (
    ResourceResponse,
    DidUrlActionState,
    DidResponse,
    DidActionState,
    SigningRequest,
    DidSuccessState,
    PartialDIDDocumentSchema,
    VerificationMethodSchema,
    DidErrorState,
    DidUrlErrorState,
    DidUrlSuccessState,
)

registrar_generate_did_doc_response = {
    "didDoc": {
        "id": "did:cheqd:testnet:123456",
        "verificationMethod": {"publicKey": "someVerificationKey"},
    }
}

registrar_create_responses = [
    DidResponse(
        jobId="MOCK_ID",
        didState=DidActionState(
            did="MOCK_ISSUER_ID",
            state="action",
            action="signPayload",
            signingRequest={
                "signingRequest0": SigningRequest(
                    kid="MOCK_KID",
                    serializedPayload="TW9jaw==",
                )
            },
        ),
    ),
    DidResponse(
        jobId="MOCK_ID",
        didState=DidSuccessState(
            did="MOCK_ISSUER_ID",
            state="finished",
            didDocument=PartialDIDDocumentSchema(
                id="did:cheqd:testnet:ca9ff47c-0286-4614-a4be-8ffa83911e09",
                controller=["did:cheqd:testnet:ca9ff47c-0286-4614-a4be-8ffa83911e09"],
                verificationMethod=[
                    VerificationMethodSchema(
                        id="did:cheqd:testnet:ca9ff47c-0286-4614-a4be-8ffa83911e09#key-1",
                        type="Ed25519VerificationKey2020",
                        controller="did:cheqd:testnet:ca9ff47c-0286-4614-a4be-8ffa83911e09",
                        publicKeyMultibase="z6Mkt9Vg1a1Jbg5a1NkToUeWH23Z33TwGUua5MrqAYUz2AL3",
                    )
                ],
                authentication=[
                    "did:cheqd:testnet:ca9ff47c-0286-4614-a4be-8ffa83911e09#key-1"
                ],
            ),
        ),
    ),
]

registrar_responses_no_signing_request = [
    DidResponse(
        jobId="MOCK_ID",
        didState=DidActionState(
            did="MOCK_ISSUER_ID",
            action="signPayload",
            state="action",
            signingRequest={},
        ),
    )
]

registrar_resource_responses_no_signing_request = [
    ResourceResponse(
        jobId="MOCK_ID",
        didUrlState=DidUrlActionState(
            didUrl="MOCK_ISSUER_ID",
            action="signPayload",
            state="action",
            signingRequest={},
        ),
    )
]

registrar_responses_network_fail = [
    DidResponse(
        jobId="MOCK_ID",
        didState=DidErrorState(
            state="error",
            reason="Network failure",
        ),
    ),
]

registrar_resource_responses_network_fail = [
    ResourceResponse(
        jobId="MOCK_ID",
        didUrlState=DidUrlErrorState(
            didUrl="MOCK_ID",
            state="error",
            reason="Network failure",
        ),
    ),
]

registrar_responses_not_finished = [
    DidResponse(
        jobId="MOCK_ID",
        didState=DidActionState(
            did="MOCK_ISSUER_ID",
            action="signPayload",
            state="action",
            signingRequest={
                "signingRequest0": SigningRequest(
                    kid="MOCK_KID",
                    serializedPayload="TW9jaw==",
                )
            },
        ),
    ),
    DidResponse(
        jobId="MOCK_ID",
        didState=DidErrorState(
            state="error",
            description="Not finished",
            reason="Not finished",
        ),
    ),
]

registrar_resource_responses_not_finished = [
    ResourceResponse(
        jobId="MOCK_ID",
        didUrlState=DidUrlActionState(
            didUrl="MOCK_ISSUER_ID",
            action="signPayload",
            state="action",
            signingRequest={
                "signingRequest0": SigningRequest(
                    kid="MOCK_KID",
                    serializedPayload="TW9jaw==",
                )
            },
        ),
    ),
    ResourceResponse(
        jobId="MOCK_ID",
        didUrlState=DidUrlErrorState(
            state="error",
            description="Not finished",
            reason="Not finished",
        ),
    ),
]

registrar_update_responses = [
    DidResponse(
        jobId="MOCK_ID",
        didState=DidActionState(
            action="signPayload",
            state="action",
            did="MOCK_ID",
            signingRequest={
                "signingRequest0": SigningRequest(
                    kid="MOCK_KID",
                    serializedPayload="TW9jaw==",
                )
            },
        ),
    ),
    DidResponse(
        jobId="MOCK_ID",
        didState=DidSuccessState(
            did="MOCK_ID",
            state="finished",
            didDocument=PartialDIDDocumentSchema(
                id="did:cheqd:testnet:ca9ff47c-0286-4614-a4be-8ffa83911e09",
                controller=["did:cheqd:testnet:ca9ff47c-0286-4614-a4be-8ffa83911e09"],
                verificationMethod=[
                    VerificationMethodSchema(
                        id="did:cheqd:testnet:ca9ff47c-0286-4614-a4be-8ffa83911e09#key-1",
                        type="Ed25519VerificationKey2020",
                        controller="did:cheqd:testnet:ca9ff47c-0286-4614-a4be-8ffa83911e09",
                        publicKeyMultibase="z6Mkt9Vg1a1Jbg5a1NkToUeWH23Z33TwGUua5MrqAYUz2AL3",
                    )
                ],
                authentication=[
                    "did:cheqd:testnet:ca9ff47c-0286-4614-a4be-8ffa83911e09#key-1"
                ],
            ),
        ),
    ),
]

registrar_deactivate_responses = [
    DidResponse(
        jobId="MOCK_ID",
        didState=DidActionState(
            action="signPayload",
            state="action",
            did="MOCK_ID",
            signingRequest={
                "signingRequest0": SigningRequest(
                    kid="MOCK_KID",
                    serializedPayload="TW9jaw==",
                )
            },
        ),
    ),
    DidResponse(
        jobId="MOCK_ID",
        didState=DidSuccessState(
            did="MOCK_ID",
            state="finished",
            didDocument=PartialDIDDocumentSchema(
                id="did:cheqd:testnet:ca9ff47c-0286-4614-a4be-8ffa83911e09",
                controller=["did:cheqd:testnet:ca9ff47c-0286-4614-a4be-8ffa83911e09"],
                verificationMethod=[
                    VerificationMethodSchema(
                        id="did:cheqd:testnet:ca9ff47c-0286-4614-a4be-8ffa83911e09#key-1",
                        type="Ed25519VerificationKey2020",
                        controller="did:cheqd:testnet:ca9ff47c-0286-4614-a4be-8ffa83911e09",
                        publicKeyMultibase="z6Mkt9Vg1a1Jbg5a1NkToUeWH23Z33TwGUua5MrqAYUz2AL3",
                    )
                ],
                authentication=[
                    "did:cheqd:testnet:ca9ff47c-0286-4614-a4be-8ffa83911e09#key-1"
                ],
            ),
        ),
        didRegistrationMetadata={"deactivated": True},
    ),
]

registrar_create_resource_responses = [
    ResourceResponse(
        jobId="MOCK_ID",
        didUrlState=DidUrlActionState(
            didUrl="MOCK_ISSUER_ID",
            action="signPayload",
            state="action",
            signingRequest={
                "signingRequest0": SigningRequest(
                    kid="MOCK_KID",
                    serializedPayload="TW9jaw==",
                )
            },
        ),
    ),
    ResourceResponse(
        jobId="MOCK_ID",
        didUrlState=DidUrlSuccessState(
            didUrl="MOCK",
            content="MOCK_VALUE",
            name="MOCK",
            type="MOCK_TYPE",
            version="MOCK_VER",
            state="finished",
        ),
    ),
]

registrar_update_resource_responses = [
    ResourceResponse(
        jobId="MOCK_ID",
        didUrlState=DidUrlActionState(
            didUrl="MOCK_ISSUER_ID",
            state="action",
            action="signPayload",
            signingRequest={
                "signingRequest0": SigningRequest(
                    kid="MOCK_KID",
                    serializedPayload="TW9jaw==",
                )
            },
        ),
    ),
    ResourceResponse(
        jobId="MOCK_ID",
        didUrlState=DidUrlSuccessState(
            didUrl="MOCK",
            content="MOCK_VALUE",
            name="MOCK",
            type="MOCK_TYPE",
            version="MOCK_VER",
            state="finished",
        ),
    ),
]


def setup_mock_registrar(
    mock_registrar,
    create_responses=registrar_create_responses,
    update_responses=registrar_update_responses,
    deactivate_responses=registrar_deactivate_responses,
    create_resource_responses=registrar_create_resource_responses,
    update_resource_responses=registrar_update_resource_responses,
):
    mock_registrar.create = AsyncMock()
    mock_registrar.create.side_effect = iter(create_responses)
    mock_registrar.update = AsyncMock()
    mock_registrar.update.side_effect = iter(update_responses)
    mock_registrar.deactivate = AsyncMock()
    mock_registrar.deactivate.side_effect = iter(deactivate_responses)
    mock_registrar.create_resource = AsyncMock()
    mock_registrar.create_resource.side_effect = iter(create_resource_responses)
    mock_registrar.update_resource = AsyncMock()
    mock_registrar.update_resource.side_effect = iter(update_resource_responses)


def setup_mock_resolver(mock_resolver, response={"MOCK_KEY": "MOCK_VALUE"}):
    mock_resolver.resolve = AsyncMock(return_value=response)
