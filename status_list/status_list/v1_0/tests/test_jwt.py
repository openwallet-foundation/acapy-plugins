import pytest

from ..jwt import jwt_sign


@pytest.mark.asyncio
async def test_jwt(context):
    headers = {"alg": "Ed25519"}
    payload = {"test": "test"}

    jwt = await jwt_sign(
        context.profile,
        headers=headers,
        payload=payload,
        verification_method="did:web:example.com#3Dn1SJNPaCXcvvJvSbsFWP2xaCjMom3can8CQNhWrTRx",
    )
    assert jwt
