"""Patch EventBus.wait_for_event to avoid InvalidStateError on late witness response.

When the controller waits for a witness response with a short timeout (e.g. 2s), the
Future is cancelled on timeout. If the witness attests later, the event bus still
delivers the event to the wait_for_event listener, which then calls
future.set_result(event) on the cancelled Future and raises InvalidStateError. This
patch adds a guard so we only call set_result when the future is not already done
(including cancelled).
"""

import asyncio
import logging
from contextlib import contextmanager

from acapy_agent.core.event_bus import EventBus

LOGGER = logging.getLogger(__name__)


def _patched_wait_for_event(
    self,
    waiting_profile,
    pattern,
    cond=None,
):
    """Capture event and retrieve value; guard set_result when future done/cancelled."""
    future = asyncio.get_event_loop().create_future()

    async def _handle_single_event(profile, event):
        if cond is not None and not cond(event):
            return
        if waiting_profile == profile:
            if not future.done():
                future.set_result(event)
            self.unsubscribe(pattern, _handle_single_event)

    self.subscribe(pattern, _handle_single_event)
    try:
        yield future
    finally:
        if not future.done():
            future.cancel()


def apply_event_bus_patch():
    """Replace EventBus.wait_for_event with a version that guards set_result."""
    _patched_wait_for_event.__name__ = "wait_for_event"
    _patched_wait_for_event.__doc__ = getattr(EventBus.wait_for_event, "__doc__", None)
    EventBus.wait_for_event = contextmanager(_patched_wait_for_event)
    LOGGER.debug(
        "Applied EventBus.wait_for_event patch (guard set_result when future.done())"
    )


# Apply as soon as this module is imported (when webvh plugin is loaded).
apply_event_bus_patch()
