"""Quick test script."""
import asyncio
from urllib.parse import urlencode
from os import getenv

from jrpc_client import JsonRpcClient, TCPSocketTransport
from controller.controller import Controller

AFJ_HOST = getenv("AFJ_HOST", "localhost")
AFJ_PORT = int(getenv("AFJ_PORT", "3000"))
ISSUER_ADMIN_ENDPOINT = getenv("ISSUER_ADMIN_ENDPOINT", "http://localhost:3001")
ISSUER_ENDPOINT = getenv("ISSUER_ENDPOINT", "http://localhost:8081")


async def main():
    """Connect to AFJ."""
    transport = TCPSocketTransport(AFJ_HOST, AFJ_PORT)
    client = JsonRpcClient(transport)
    controller = Controller(ISSUER_ADMIN_ENDPOINT)
    async with transport, client, controller:
        result = await client.request("initialize")
        print(result)
        supported = await controller.post(
            "/oid4vci/credential-supported/create",
            json={
                "cryptographic_binding_methods_supported": ["did"],
                "cryptographic_suites_supported": ["EdDSA"],
                "format": "jwt_vc_json",
                "id": "UniversityDegreeCredential",
                "types": ["VerifiableCredential", "UniversityDegreeCredential"],
            },
        )
        exchange = await controller.post(
            "/oid4vci/exchange/create",
            json={
                "supported_cred_id": supported["supported_cred_id"],
                "credential_ubject": {"name": "alice"},
            },
        )
        offer = await controller.get(
            "/oid4vci/credential-offer",
            params={"exchange_id": exchange["exchange_id"]},
        )
        offer_uri = "openid-credential-offer://" + urlencode(offer)
        result = await client.request("receiveCredentialOffer", offer=offer_uri)


if __name__ == "__main__":
    asyncio.run(main())
