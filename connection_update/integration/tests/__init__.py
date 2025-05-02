# pylint: disable=redefined-outer-name

from functools import wraps

import pytest
import requests

AUTO_ACCEPT = "false"

BOB = "http://bob:3001"
ALICE = "http://alice:3001"


def get(agent: str, path: str, **kwargs):
    """Get."""
    return requests.get(f"{agent}{path}", **kwargs)


def post(agent: str, path: str, **kwargs):
    """Post."""
    return requests.post(f"{agent}{path}", **kwargs)


def put(agent: str, path: str, **kwargs):
    """Put."""
    return requests.put(f"{agent}{path}", **kwargs)


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
    @fail_if_not_ok("Create invitation failed")
    def create_invitation(self, body: dict, **kwargs):
        """Create invitation."""
        return post(self.url, "/out-of-band/create-invitation", params=kwargs, json=body)

    @unwrap_json_response
    @fail_if_not_ok("Receive invitation failed")
    def receive_invite(self, invite: dict, **kwargs):
        """Receive invitation."""
        return post(
            self.url, "/out-of-band/receive-invitation", params=kwargs, json=invite
        )

    @unwrap_json_response
    @fail_if_not_ok("Failed to send basic message")
    def connections_update(self, connection_id, alias):
        """Set connection metadata."""
        return put(
            self.url,
            f"/connections/{connection_id}",
            json={"alias": alias},
        )

    @unwrap_json_response
    @fail_if_not_ok("Failed to send basic message")
    def get_connection(self, connection_id):
        """Set connection metadata."""
        return get(
            self.url,
            f"/connections/{connection_id}",
        )

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

    def put(self, path: str, return_json: bool = True, fail_with: str = None, **kwargs):
        """Do get to agent endpoint."""
        wrapped_put = put
        if fail_with:
            wrapped_put = fail_if_not_ok(fail_with)(wrapped_put)
        if return_json:
            wrapped_put = unwrap_json_response(wrapped_put)

        return wrapped_put(self.url, path, **kwargs)
