import pytest
from unittest.mock import MagicMock

from ..routes import register, post_process_routes


@pytest.mark.asyncio
async def test_register_routes():
    mock_app = MagicMock()
    mock_app.add_routes = MagicMock()

    await register(mock_app)
    mock_app.add_routes.assert_called_once()


@pytest.mark.asyncio
async def test_post_process_routes():
    mock_app = MagicMock(_state={"swagger_dict": {}})
    post_process_routes(mock_app)
    assert "tags" in mock_app._state["swagger_dict"]
