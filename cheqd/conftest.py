"""Pytest configuration for the cheqd plugin test suite."""

import inspect
from unittest.mock import Mock

import aioresponses.core
from aiohttp import ClientResponse

# aiohttp 3.14 added a required keyword-only `stream_writer` argument to
# ClientResponse.__init__, but aioresponses (as of 0.7.9, the latest release)
# doesn't pass it, breaking every aioresponses-based test in this plugin
# (test_registrar.py, test_resolver.py) with:
#   TypeError: ClientResponse.__init__() missing 1 required keyword-only
#   argument: 'stream_writer'
# Upstream fix (unreleased): https://github.com/pnuckowski/aioresponses/pull/288
#
# To remove this shim: once aioresponses publishes a release containing that
# fix, bump the `aioresponses` pin in pyproject.toml, run `poetry lock`, and
# delete this file. The `inspect.signature` guard below makes this a no-op
# against any aioresponses version that already sets `stream_writer` itself,
# so it's also safe to leave in place a little longer than strictly needed.
if "stream_writer" in inspect.signature(ClientResponse.__init__).parameters:

    class _PatchedClientResponse(ClientResponse):
        def __init__(self, *args, **kwargs):
            kwargs.setdefault("stream_writer", Mock(output_size=0))
            super().__init__(*args, **kwargs)

    aioresponses.core.ClientResponse = _PatchedClientResponse
