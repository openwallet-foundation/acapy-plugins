import json
from functools import wraps
from typing import Optional

import pytest
import requests

ADMIN = "http://admin:3001"


def get(agent: str, path: str, token: Optional[str] = None, **kwargs):
    # """Get."""
    if token:
        headers = {"Authorization": "Bearer " + token}
    else:
        headers = None

    return requests.get(f"{agent}{path}", headers=headers, **kwargs)


def post(agent: str, path: str, data: any, **kwargs):
    """Post."""
    return requests.post(f"{agent}{path}", data=json.dumps(data), **kwargs)


def fail_if_not_ok(message: str):
    """Fail the current test if wrapped call fails with message."""

    def _fail_if_not_ok(func):
        @wraps(func)
        def _wrapper(*args, **kwargs):
            response = func(*args, **kwargs)
            if not response.ok:
                pytest.fail(f"{message}: {response.content}")
            return response

        return _wrapper

    return _fail_if_not_ok


def unwrap_json_response(func):
    """Unwrap a requests response object to json."""

    @wraps(func)
    def _wrapper(*args, **kwargs) -> dict:
        response = func(*args, **kwargs)
        return response.json()

    return _wrapper


class Agent:
    """Class for interacting with Agent over Admin API"""

    def __init__(self, url: str):
        self.url = url

    @unwrap_json_response
    @fail_if_not_ok("Failed to create wallet")
    def create_wallet(self, payload):
        """Create wallet."""
        return post(self.url, path="/multitenancy/wallet", data=payload)

    @unwrap_json_response
    @fail_if_not_ok("Failed to remove wallet")
    def remove_wallet(self, wallet_id: str, payload: dict = None):
        """Remove wallet."""
        return post(
            self.url, path=f"/multitenancy/wallet/{wallet_id}/remove", data=payload
        )

    @unwrap_json_response
    @fail_if_not_ok("Failed to get token")
    def get_token(self, wallet_id: str, payload: dict = {}):
        """Create wallet."""
        return post(
            self.url, path=f"/multitenancy/wallet/{wallet_id}/token", data=payload
        )

    @unwrap_json_response
    @fail_if_not_ok("Failed to get wallets")
    def get_wallets(self, **kwargs):
        """Get wallets."""
        return get(self.url, path="/multitenancy/wallets", **kwargs)

    def get_connections(self, token, **kwargs):
        """Get connections."""
        return get(self.url, path="/connections", token=token, **kwargs)

    def get(self, path: str, return_json: bool = True, fail_with: str = None, **kwargs):
        """Do get to agent endpoint."""
        wrapped_get = get
        if fail_with:
            wrapped_get = fail_if_not_ok(fail_with)(wrapped_get)
        if return_json:
            wrapped_get = unwrap_json_response(wrapped_get)

        return wrapped_get(self.url, path, **kwargs)

    def post(self, path: str, return_json: bool = True, fail_with: str = None, **kwargs):
        """Do get to agent endpoint."""
        wrapped_post = post
        if fail_with:
            wrapped_post = fail_if_not_ok(fail_with)(wrapped_post)
        if return_json:
            wrapped_post = unwrap_json_response(wrapped_post)

        return wrapped_post(self.url, path, **kwargs)
