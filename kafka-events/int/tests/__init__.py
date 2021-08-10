import asyncio
import json
from aiokafka import AIOKafkaConsumer
from aiohttp import web
from aries_staticagent import StaticConnection, Module
from aries_cloudagent.core.event_bus import MockEventBus

class BaseAgent:
    """Simple Agent class.
    Used to start up an agent with statically configured handlers.
    """

    def __init__(self, host: str, port: int, connection: StaticConnection):
        """Initialize BaseAgent."""
        self.host = host
        self.port = port
        self.connection = connection
        self._runner = None
        self.mock_event_bus = MockEventBus()
    async def handle_web_request(self, request: web.Request):
        """Handle HTTP POST."""
        response = []
        with self.connection.session(response.append) as session:
            await self.connection.handle(await request.read(), session)

        if response:
            return web.Response(body=response.pop())

        raise web.HTTPAccepted()

    async def start_async(self):
        """Start the agent listening for HTTP POSTs."""
        app = web.Application()
        app.add_routes([web.post("/", self.handle_web_request)])
        self.runner = web.AppRunner(app)
        await self.runner.setup()
        site = web.TCPSite(self.runner, self.host, self.port)
        await site.start()
        loop = asyncio.get_event_loop()
        # TODO: add proper config retrieval from docker config
        consumer = AIOKafkaConsumer(
            **{"bootstrap_servers": "kafka", "group_id": "aca-py-events"}
        )
        await consumer.start()
        consumer.subscribe(pattern="acapy.*")

        async def consume():
            async for msg in consumer:
                topic = str(msg.topic).replace("-", "::")
                self.mock_event_bus.notify(topic, json.loads(msg.value))

        loop.create_task(consume())

    async def cleanup(self):
        """Clean up async start."""
        await self.runner.cleanup()

    def start(self):
        """Start sychronously."""
        app = web.Application()
        app.add_routes([web.post("/", self.handle_web_request)])

        web.run_app(app, port=self.port)

    def register_modules(self, *modules: Module):
        """Register modules on connection."""
        for module in modules:
            self.connection.route_module(module)
