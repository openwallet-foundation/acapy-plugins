import asyncio
from dataclasses import dataclass
import threading

from aiohttp import web


@dataclass
class WebHookListener:
    # Contains callback functions to handle webhooks
    webhook_handler: object

    async def _handle_webhook(self, request: web.Request):
        """Upon webhook firing, finds method defined in webhook_handler
        with name "handle_<topic_name>" and runs it with arg message"""
        topic = request.match_info["topic"]
        payload = await request.json()

        handler = f"handle_{topic}"
        method = getattr(self.webhook_handler, handler, None)

        if not method:
            raise Exception(f"Topic {topic} has no registered handler")
        else:
            asyncio.get_event_loop().create_task(method(payload))

        return web.Response(status=200)

    def listen_webhooks(self):
        """Launch daemon thread that creates server listening for webhook requests."""

        def _run_server():
            app = web.Application()
            app.add_routes(
                [web.post(path="/webhooks/topic/{topic}/", handler=self._handle_webhook)]
            )
            runner = web.AppRunner(app)

            loop = asyncio.new_event_loop()

            asyncio.set_event_loop(loop)
            loop.run_until_complete(runner.setup())

            site = web.TCPSite(runner=runner, host="0.0.0.0", port=3008)

            loop.run_until_complete(site.start())
            loop.run_forever()

        threading.Thread(
            target=_run_server,
            daemon=True,  # So that it will end if main thread ends
        ).start()
