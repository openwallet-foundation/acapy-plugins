import asyncio
from pathlib import Path

from .jsonrpc import JsonRpcClient, UnixSocketTransport


async def main():
    """Connect to AFJ."""
    transport = UnixSocketTransport(
        str(Path(__file__).parent.parent / "afj/agent.sock")
    )
    client = JsonRpcClient(transport)
    async with transport, client:
        result = await client.send_request("initialize")
        print(result)


if __name__ == "__main__":
    asyncio.run(main())
