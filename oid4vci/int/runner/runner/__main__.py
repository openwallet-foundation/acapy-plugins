"""Quick test script."""
import asyncio
from os import getenv

from .afj_wrapper.jsonrpc import JsonRpcClient, TCPSocketTransport

AFJ_HOST = getenv("AFJ_HOST", "localhost")
AFJ_PORT = int(getenv("AFJ_PORT", "3000"))
ISSUER_ENDPOINT = getenv("ISSUER_ENDPOINT", "http://localhost:8081")


async def main():
    """Connect to AFJ."""
    transport = TCPSocketTransport(AFJ_HOST, AFJ_PORT)
    client = JsonRpcClient(transport)
    async with transport, client:
        result = await client.request("initialize")
        print(result)
        result = await client.request(
            "requestCredentialUsingPreAuthorized", issuerUri=ISSUER_ENDPOINT
        )


if __name__ == "__main__":
    asyncio.run(main())
