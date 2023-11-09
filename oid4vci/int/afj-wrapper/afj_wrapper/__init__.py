import asyncio
from os import getenv

from .jsonrpc import JsonRpcClient, TCPSocketTransport

AFJ_HOST = getenv("AFJ_HOST", "localhost")
AFJ_PORT = int(getenv("AFJ_PORT", "3000"))


async def main():
    """Connect to AFJ."""
    transport = TCPSocketTransport(AFJ_HOST, AFJ_PORT)
    client = JsonRpcClient(transport)
    async with transport, client:
        result = await client.request(
            "initialize",
            endpoint="http://localhost:3001",
            host="0.0.0.0",
            port=3001,
        )
        print(result)


if __name__ == "__main__":
    asyncio.run(main())
