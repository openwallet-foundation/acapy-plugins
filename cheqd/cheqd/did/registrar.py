"""DID Registrar for Cheqd."""

from aiohttp import ClientSession, web

from ..did.base import (
    BaseDIDRegistrar,
    DidCreateRequestOptions,
    DidUpdateRequestOptions,
    DidDeactivateRequestOptions,
    ResourceCreateRequestOptions,
    ResourceUpdateRequestOptions,
    SubmitSignatureOptions,
)


class CheqdDIDRegistrar(BaseDIDRegistrar):
    """DID Registrar implementation for did:cheqd."""

    DID_REGISTRAR_BASE_URL = "http://localhost:3000/1.0/"

    def __init__(self, registrar_url: str = None) -> None:
        """Initialize the Cheqd Registrar."""
        super().__init__()
        if registrar_url:
            self.DID_REGISTRAR_BASE_URL = registrar_url

    async def create(
        self, options: DidCreateRequestOptions | SubmitSignatureOptions
    ) -> dict | None:
        """Create a DID Document."""
        async with ClientSession() as session:
            try:
                async with session.post(
                    self.DID_REGISTRAR_BASE_URL + "create",
                    json=options.dict(exclude_none=True),
                ) as response:
                    if response.status == 200 or response.status == 201:
                        return await response.json()
                    elif response.status == 400:
                        res = await response.json()
                        did_state = res.get("didState")
                        raise web.HTTPBadRequest(reason=did_state.get("reason"))
                    else:
                        raise web.HTTPInternalServerError()
            except Exception:
                raise

    async def update(
        self, options: DidUpdateRequestOptions | SubmitSignatureOptions
    ) -> dict:
        """Update a DID Document."""
        async with ClientSession() as session:
            try:
                async with session.post(
                    self.DID_REGISTRAR_BASE_URL + "update",
                    json=options.dict(exclude_none=True),
                ) as response:
                    if response.status == 200 or response.status == 201:
                        return await response.json()
                    elif response.status == 400:
                        res = await response.json()
                        did_state = res.get("didState")
                        raise web.HTTPBadRequest(reason=did_state.get("reason"))
                    else:
                        raise web.HTTPInternalServerError()
            except Exception:
                raise

    async def deactivate(
        self, options: DidDeactivateRequestOptions | SubmitSignatureOptions
    ) -> dict:
        """Deactivate a DID Document."""
        async with ClientSession() as session:
            try:
                async with session.post(
                    self.DID_REGISTRAR_BASE_URL + "deactivate",
                    json=options.dict(exclude_none=True),
                ) as response:
                    if response.status == 200 or response.status == 201:
                        return await response.json()
                    elif response.status == 400:
                        res = await response.json()
                        did_state = res.get("didState")
                        raise web.HTTPBadRequest(reason=did_state.get("reason"))
                    else:
                        raise web.HTTPInternalServerError()
            except Exception:
                raise

    async def create_resource(
        self, options: ResourceCreateRequestOptions | SubmitSignatureOptions
    ) -> dict:
        """Create a DID Linked Resource."""
        async with ClientSession() as session:
            try:
                async with session.post(
                    self.DID_REGISTRAR_BASE_URL + "createResource",
                    json=options.dict(exclude_none=True),
                ) as response:
                    if response.status == 200 or response.status == 201:
                        return await response.json()
                    else:
                        raise web.HTTPInternalServerError()
            except Exception:
                raise

    async def update_resource(
        self, options: ResourceUpdateRequestOptions | SubmitSignatureOptions
    ) -> dict:
        """Update a DID Linked Resource."""
        async with ClientSession() as session:
            try:
                async with session.post(
                    self.DID_REGISTRAR_BASE_URL + "updateResource",
                    json=options.dict(exclude_none=True),
                ) as response:
                    if response.status == 200 or response.status == 201:
                        return await response.json()
                    else:
                        raise web.HTTPInternalServerError()
            except Exception:
                raise

    async def deactivate_resource(self, options: dict) -> dict:
        """Deactivate a DID Linked Resource."""
        raise NotImplementedError("This method will not be implemented for did:cheqd.")
