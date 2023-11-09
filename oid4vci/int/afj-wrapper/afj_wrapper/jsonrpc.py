import asyncio
import json
from typing import Any, Dict, Optional, Protocol
from async_selective_queue import AsyncSelectiveQueue


class TransportProtocol(Protocol):
    """Transport protocol that transport class should implement."""

    async def send(self, message: str) -> None:
        ...

    async def receive(self) -> str:
        ...


class JsonRpcError(Exception):
    def __init__(self, error: dict):
        self.code = error.get("code")
        self.message = error.get("message")
        self.data = error.get("data")
        super().__init__(self.__str__())

    def __str__(self) -> str:
        error_str = f"JSON-RPC Error {self.code}: {self.message}"
        if isinstance(self.data, str):
            # Represent newlines in data correctly when converting to string
            data = self.data.replace("\\n", "\n")
            error_str += f"\nData: {data}"
        return error_str


class JsonRpcClient:
    """JSON-RPC client implementation."""

    def __init__(self, transport: TransportProtocol) -> None:
        self.transport = transport
        self.id_counter = 0
        self.pending_calls: Dict[int, asyncio.Future] = {}
        self.receive_task: Optional[asyncio.Task] = None
        self._notification_queue: Optional[AsyncSelectiveQueue[dict]] = None

    @property
    def notification_queue(self) -> AsyncSelectiveQueue[dict]:
        """Queue of notifications received from the server."""
        if not self._notification_queue:
            raise Exception("Client not started")
        return self._notification_queue

    async def start(self) -> None:
        """Start the client."""
        self._notification_queue = AsyncSelectiveQueue()
        self.receive_task = asyncio.create_task(self.receive_response())

    async def stop(self) -> None:
        """Close the client."""
        # Stop the receive task
        if self.receive_task:
            self.receive_task.cancel()
            try:
                await self.receive_task
            except asyncio.CancelledError:
                pass
        # Cancel all pending calls
        for future in self.pending_calls.values():
            future.cancel()

        # Clear the pending calls dictionary
        self.pending_calls.clear()

    async def __aenter__(self) -> "JsonRpcClient":
        """Async context manager: start the client."""
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager: close the client."""
        await self.stop()

    async def send_request(
        self, method: str, params: Optional[Dict[str, Any]] = None
    ) -> Any:
        self.id_counter += 1
        message_id = self.id_counter
        request = {
            "jsonrpc": "2.0",
            "method": method,
            "id": message_id,
        }
        if params is not None:
            request["params"] = params
        message = json.dumps(request)
        await self.transport.send(message)
        future = asyncio.get_event_loop().create_future()
        self.pending_calls[message_id] = future
        return await future

    async def receive_response(self) -> None:
        while True:
            response_str = await self.transport.receive()
            response = json.loads(response_str)
            message_id = response.get("id")
            if not message_id:
                # This is a notification
                await self.notification_queue.put(response)
            if message_id in self.pending_calls:
                future = self.pending_calls.pop(message_id)
                if "result" in response:
                    future.set_result(response["result"])
                elif "error" in response:
                    future.set_exception(JsonRpcError(response["error"]))
                else:
                    future.set_exception(Exception("Invalid JSON-RPC response"))


class UnixSocketTransport:
    """Transport implementation that uses a Unix socket."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None

    async def connect(self) -> None:
        self.reader, self.writer = await asyncio.open_unix_connection(self.path)

    async def send(self, message: str) -> None:
        if self.writer is None:
            raise Exception("Transport is not connected")
        self.writer.write(message.encode())
        await self.writer.drain()

    async def receive(self) -> str:
        if self.reader is None:
            raise Exception("Transport is not connected")
        data = await self.reader.read(4096)  # Adjust buffer size as needed
        return data.decode()

    async def close(self) -> None:
        if self.writer is not None:
            self.writer.close()
            await self.writer.wait_closed()

    async def __aenter__(self) -> "UnixSocketTransport":
        """Async context manager: connect to the socket."""
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager: close the socket."""
        await self.close()


async def main():
    """Usage example."""

    class DummyTransport:
        """Dummy transport implementation that prints messages to the console."""

        async def send(self, message: str) -> None:
            print(f"Sending message: {message}")

        async def receive(self) -> str:
            # Simulate a response (In a real implementation, you would receive messages from a server)
            await asyncio.sleep(1)
            return json.dumps({"jsonrpc": "2.0", "result": "pong", "id": 1})

    transport = DummyTransport()
    client = JsonRpcClient(transport)

    await client.start()  # Start the client

    try:
        # Example of sending a request
        result = await client.send_request("ping")
        print(f"Received result: {result}")
    finally:
        # Ensure the client is properly closed
        await client.stop()


# Run the asyncio event loop
if __name__ == "__main__":
    asyncio.run(main())
