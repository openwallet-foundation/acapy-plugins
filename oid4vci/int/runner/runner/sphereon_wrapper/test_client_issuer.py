import pytest
import asyncio
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from jose import JWTError
from jose.constants import ALGORITHMS
from jose.backends import RSAKey
from ssi import ExpressBuilder
from oid4vci import (
    VcIssuerBuilder,
    OID4VCIServer,
    AccessTokenResponse,
    CredentialOfferSession,
    CredentialSupportedBuilderV1_11,
    OpenId4VCIClient,
)
from oid4vci_common import (
    Alg,
    IssuerCredentialSubjectDisplay,
    CredentialSupported,
    Jwt,
    JWTHeader,
    JWTPayload,
    OpenId4VCIVersion,
)
from oid4vci_issuer import MemoryStates
from did_resolver import DIDDocument
from did_key.driver import driver as didKeyDriver
from did_key.key import KeyObject
import jose


@pytest.fixture
async def subject_did_key():
    did_kd = didKeyDriver()
    return await did_kd.generate()


@pytest.fixture
async def subject_keypair():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return KeyPair(public_key, private_key)


class KeyPair:
    def __init__(self, public_key, private_key):
        self.public_key = public_key
        self.private_key = private_key


@pytest.fixture
def express_support():
    return ExpressBuilder.from_server_opts(port=3456, hostname="localhost").build(
        start_listening=False
    )


@pytest.fixture
async def vc_issuer(express_support, subject_keypair, subject_did_key):
    issuer_url = "http://localhost:3456/test"
    state_manager = MemoryStates()
    credential_supported = (
        CredentialSupportedBuilderV1_11()
        .with_cryptographic_suites_supported("ES256K")
        .with_cryptographic_binding_method("did")
        .with_types("VerifiableCredential")
        .with_format("jwt_vc_json")
        .with_id("UniversityDegree_JWT")
        .with_credential_supported_display(
            IssuerCredentialSubjectDisplay(
                name="University Credential",
                locale="en-US",
                logo={
                    "url": "https://exampleuniversity.com/public/logo.png",
                    "alt_text": "a square logo of a university",
                },
                background_color="#12107c",
                text_color="#FFFFFF",
            )
        )
        .add_credential_subject_property_display(
            "given_name",
            IssuerCredentialSubjectDisplay(name="given name", locale="en-US"),
        )
        .build()
    )

    credential = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": ["VerifiableCredential"],
        "issuer": "did:key:test",
        "issuanceDate": "2023-01-01T00:00:00Z",
        "credentialSubject": {},
    }

    vc_issuer = (
        VcIssuerBuilder()
        .with_credential_endpoint("http://localhost:3456/test/credential-endpoint")
        .with_default_credential_offer_base_uri("http://localhost:3456/test")
        .with_credential_issuer(issuer_url)
        .with_issuer_display(name="example issuer", locale="en-US")
        .with_credentials_supported(credential_supported)
        .with_credential_offer_state_manager(state_manager)
        .with_in_memory_c_nonce_state()
        .with_in_memory_credential_offer_uri_state()
        .with_credential_data_supplier(
            lambda: asyncio.ensure_future(
                {
                    "format": "ldp_vc",
                    "credential": credential,
                }
            )
        )
        .with_credential_signer_callback(
            lambda: asyncio.ensure_future(
                {
                    **credential,
                    "proof": {
                        "type": "JwtProof2020",
                        "jwt": "ye.ye.ye",
                        "created": "2023-01-01T00:00:00Z",
                        "proofPurpose": "assertionMethod",
                        "verificationMethod": "sdfsdfasdfasdfasdfasdfassdfasdf",
                    },
                }
            )
        )
        .with_jwt_verify_callback(lambda args: asyncio.ensure_future(verify_jwt(args)))
        .build()
    )

    return vc_issuer


async def verify_jwt(args):
    header = jose.decode_protected_header(args["jwt"])
    payload = jose.decode_jwt(args["jwt"])

    kid = header.get("kid") or args.get("kid")
    did = kid.split("#")[0]
    did_document = DIDDocument("@context=https://www.w3.org/ns/did/v1", id=did)
    alg = header.get("alg", "ES256k")
    return {
        "alg": alg,
        "kid": kid,
        "did": did,
        "didDocument": did_document,
        "jwt": {
            "header": header,
            "payload": payload,
        },
    }


@pytest.fixture
async def server(express_support, vc_issuer):
    server = OID4VCIServer(
        express_support,
        issuer=vc_issuer,
        base_url="http://localhost:3456/test",
        endpoint_opts={
            "token_endpoint_opts": {
                "accessTokenSignerCallback": lambda jwt, kid=None: asyncio.ensure_future(
                    sign_access_token(jwt, kid)
                ),
                "tokenPath": "/test/token",
            },
        },
    )
    await express_support.start()
    return server


async def sign_access_token(jwt, kid=None):
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    return (
        jose.SignJWT(jwt["payload"])
        .set_protected_header(jwt["header"])
        .sign(private_key)
    )


@pytest.mark.asyncio
async def test_vc_issuer(
    server, vc_issuer, express_support, subject_keypair, subject_did_key
):
    issuer_state = "previously-created-state"
    pre_authorized_code = "test_code"

    async with OpenId4VCIClient.from_uri(
        uri=await vc_issuer.create_credential_offer_uri(
            grants={
                "authorization_code": {
                    "issuer_state": issuer_state,
                },
                "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                    "pre-authorized_code": pre_authorized_code,
                    "user_pin_required": True,
                },
            },
            credentials=["UniversityDegree_JWT"],
            scheme="http",
        ),
        kid=subject_did_key["didDocument"]["authentication"][0],
        alg="ES256",
    ) as client:
        assert server.issuer is not None
        assert client.credential_offer == {
            "baseUrl": "http://localhost:3456/test",
            "credential_offer": {
                "credential_issuer": "http://localhost:3456/test",
                "credentials": ["UniversityDegree_JWT"],
                "grants": {
                    "authorization_code": {
                        "issuer_state": "previously-created-state",
                    },
                    "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                        "pre-authorized_code": "test_code",
                        "user_pin_required": True,
                    },
                },
            },
            "issuerState": "previously-created-state",
            "original_credential_offer": {
                "credential_issuer": "http://localhost:3456/test",
                "credentials": ["UniversityDegree_JWT"],
                "grants": {
                    "authorization_code": {
                        "issuer_state": "previously-created-state",
                    },
                    "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                        "pre-authorized_code": "test_code",
                        "user_pin_required": True,
                    },
                },
            },
            "preAuthorizedCode": "test_code",
            "scheme": "http",
            "supportedFlows": ["Authorization Code Flow", "Pre-Authorized Code Flow"],
            "userPinRequired": True,
            "version": 1011,
        }
        assert client.get_issuer() == "http://localhost:3456/test"
        assert client.version() == OpenId4VCIVersion.VER_1_0_11

        metadata = await client.retrieve_server_metadata()
        assert metadata == {
            "authorizationServerType": "OID4VCI",
            "authorization_server": "http://localhost:3456/test",
            "credentialIssuerMetadata": {
                "credential_endpoint": "http://localhost:3456/test/credential-endpoint",
                "credential_issuer": "http://localhost:3456/test",
                "credentials_supported": [
                    {
                        "credentialSubject": {
                            "given_name": {
                                "locale": "en-US",
                                "name": "given name",
                            },
                        },
                        "cryptographic_binding_methods_supported": ["did"],
                        "cryptographic_suites_supported": ["ES256K"],
                        "display": [
                            {
                                "background_color": "#12107c",
                                "locale": "en-US",
                                "logo": {
                                    "alt_text": "a square logo of a university",
                                    "url": "https://exampleuniversity.com/public/logo.png",
                                },
                                "name": "University Credential",
                                "text_color": "#FFFFFF",
                            },
                        ],
                        "format": "jwt_vc_json",
                        "id": "UniversityDegree_JWT",
                        "types": ["VerifiableCredential"],
                    },
                ],
                "display": [
                    {
                        "locale": "en-US",
                        "name": "example issuer",
                    },
                ],
            },
            "credential_endpoint": "http://localhost:3456/test/credential-endpoint",
            "issuer": "http://localhost:3456/test",
            "token_endpoint": "http://localhost:3456/test/token",
        }

        pre_auth_code = (
            client.credential_offer["credential_offer"]["grants"]
            .get("urn:ietf:params:oauth:grant-type:pre-authorized_code", {})
            .get("pre-authorized_code")
        )
        assert pre_auth_code is not None

        cred_offer_session = await vc_issuer.credential_offer_sessions.get_asserted(
            pre_auth_code
        )
        assert cred_offer_session is not None

        access_token = await client.acquire_access_token(
            pin=cred_offer_session["userPin"]
        )
        assert access_token is not None

        async def proof_of_possession_callback_function(args):
            return (
                await jose.SignJWT(args["payload"])
                .set_protected_header(args["header"])
                .set_issued_at(int(datetime.datetime.utcnow().timestamp()))
                .set_issuer(args["kid"])
                .set_audience(args["payload"]["aud"])
                .set_expiration_time(2 * 3600)
                .sign(subject_keypair.private_key)
            )

        credential_response = await client.acquire_credentials(
            credential_types=["VerifiableCredential"],
            format="jwt_vc_json",
            proof_callbacks={"signCallback": proof_of_possession_callback_function},
        )

        assert credential_response == {
            "c_nonce_expires_in": 300000,
            "credential": {
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                "credentialSubject": {},
                "issuer": "did:key:test",
                "proof": {
                    "jwt": "ye.ye.ye",
                    "proofPurpose": "assertionMethod",
                    "type": "JwtProof2020",
                    "verificationMethod": "sdfsdfasdfasdfasdfasdfassdfasdf",
                },
                "type": ["VerifiableCredential"],
            },
            "format": "jwt_vc_json",
        }


@pytest.fixture
def event_loop():
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()
