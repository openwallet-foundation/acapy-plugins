from logging import WARN
from unittest.mock import AsyncMock, MagicMock, patch

from acapy_agent.resolver.did_resolver import DIDResolver
from hedera import setup


class TestInit:
    class TestSetup:
        async def test_sucess(self, context):
            await setup(context)

        async def test_no_did_resolver(self, caplog):
            context = MagicMock(inject_or=MagicMock(return_value=None))

            await setup(context)

            assert caplog.record_tuples == [
                ("hedera", WARN, "No DID Resolver instance found in context")
            ]

        @patch("hedera.HederaDIDResolver")
        async def test_no_anoncreds_registry(self, mock_hedera_did_resolver, caplog):
            context = MagicMock(
                inject_or=MagicMock(
                    side_effect=lambda x: DIDResolver() if x == DIDResolver else None
                ),
            )

            mock_hedera_did_resolver.return_value.setup = AsyncMock(return_value=None)

            await setup(context)

            assert caplog.record_tuples == [
                ("hedera", WARN, "No AnonCredsRegistry instance found in context")
            ]
