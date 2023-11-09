"""JSON-RPC client implementation."""
from abc import ABC, abstractmethod
import asyncio
import json
from typing import Any, Dict, Optional, Protocol
from async_selective_queue import AsyncSelectiveQueue


class TransportProtocol(Protocol):
    """Transport protocol that transport class should implement."""

    async def send(self, message: str) -> None:
        """Send a message to connected clients."""
        ...

    async def receive(self) -> str:
        """Receive a message from connected clients."""
        ...


class JsonRpcError(Exception):
    """Exception raised when an error is returned by the server."""

    def __init__(self, error: dict):
        """Initialize the exception."""
        self.code = error.get("code")
        self.message = error.get("message")
        self.data = error.get("data")
        super().__init__(self.__str__())

    def __str__(self) -> str:
        """Convert the exception to a string."""
        error_str = f"JSON-RPC Error {self.code}: {self.message}"
        if isinstance(self.data, str):
            # Represent newlines in data correctly when converting to string
            data = self.data.replace("\\n", "\n")
            error_str += f"\nData: {data}"
        return error_str


class JsonRpcClient:
    """JSON-RPC client implementation."""

    def __init__(self, transport: TransportProtocol) -> None:
        """Initialize the client."""
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

    async def request(self, method: str, **params: Any) -> Any:
        """Send a request to the server."""
        return await self.send_request(method, params)

    async def send_request(
        self, method: str, params: Optional[Dict[str, Any]] = None
    ) -> Any:
        """Send a request to the server."""
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
        """Receive responses from the server."""
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


class BaseSocketTransport(ABC):
    """Base transport implementation using asyncio sockets."""

    def __init__(self) -> None:
        """Initialize the transport."""
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None

    async def send(self, message: str) -> None:
        """Send a message to connected clients."""
        if self.writer is None:
            raise Exception("Transport is not connected")

        message_bytes = message.encode()
        header = f"length: {len(message_bytes)}\n".encode()
        full_message = header + message_bytes

        self.writer.write(full_message)
        await self.writer.drain()

    async def receive(self) -> str:
        """Receive a message from connected clients."""
        if self.reader is None:
            raise Exception("Transport is not connected")

        # Read the header first
        header = await self.reader.readuntil(b"\n")
        # Decode the header and extract the length
        length_str = header.decode().strip()
        if not length_str.startswith("length: "):
            raise ValueError("Invalid message header received")

        # Extract the length and convert to an integer
        length = int(length_str.split("length: ")[1].strip())

        # Now read the body of the message
        body_bytes = await self.reader.readexactly(length)

        # Decode and return the message body
        return body_bytes.decode()

    async def close(self) -> None:
        """Close the transport."""
        if self.writer is not None:
            self.writer.close()
            await self.writer.wait_closed()

    async def __aenter__(self) -> "BaseSocketTransport":
        """Async context manager: connect to the server."""
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager: close the transport."""
        await self.close()

    @abstractmethod
    async def connect(self):
        """Connect to the server."""


class UnixSocketTransport(BaseSocketTransport):
    """Transport implementation that uses a Unix socket."""

    def __init__(self, path: str) -> None:
        """Initialize the transport."""
        super().__init__()
        self.path = path

    async def connect(self) -> None:
        """Connect to the server."""
        self.reader, self.writer = await asyncio.open_unix_connection(self.path)


class TCPSocketTransport(BaseSocketTransport):
    """Transport implementation that uses a TCP socket."""

    def __init__(self, host: str, port: int) -> None:
        """Initialize the transport."""
        super().__init__()
        self.host = host
        self.port = port

    async def connect(self) -> None:
        """Connect to the server."""
        self.reader, self.writer = await asyncio.open_connection(self.host, self.port)


async def main():
    """Usage example."""

    class DummyTransport:
        """Dummy transport implementation that prints messages to the console."""

        async def send(self, message: str) -> None:
            """Send a message to connected clients."""
            print(f"Sending message: {message}")

        async def receive(self) -> str:
            """Receive a message from connected clients."""
            # Simulate a response (In a real implementation, you would receive
            # messages from a server)
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
