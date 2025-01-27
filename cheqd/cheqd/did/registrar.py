"""DID Registrar for Cheqd."""

import logging
from aiohttp import ClientSession
from pydantic import ValidationError

from ..did.base import (
    DidResponse,
    BaseDIDRegistrar,
    DidCreateRequestOptions,
    DidDeactivateRequestOptions,
    DidUpdateRequestOptions,
    ResourceCreateRequestOptions,
    ResourceUpdateRequestOptions,
    SubmitSignatureOptions,
    ResourceResponse,
    CheqdDIDRegistrarError,
)

LOGGER = logging.getLogger(__name__)


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
    ) -> DidResponse:
        """Create a DID Document."""
        async with ClientSession() as session:
            try:
                async with session.post(
                    self.DID_REGISTRAR_BASE_URL + "create",
                    json=options.model_dump(exclude_none=True),
                ) as response:
                    try:
                        res = await response.json()
                    except Exception:
                        raise CheqdDIDRegistrarError(
                            "cheqd: did-registrar: create: Unable to parse JSON"
                        )
                    if not res:
                        raise CheqdDIDRegistrarError(
                            "cheqd: did-registrar: create: Response is None."
                        )

                    return DidResponse(**res)
            except (ValidationError, AttributeError):
                raise CheqdDIDRegistrarError(
                    "cheqd: did-registrar: create: Response Format is invalid"
                )
            except Exception:
                raise

    async def update(
        self, options: DidUpdateRequestOptions | SubmitSignatureOptions
    ) -> DidResponse:
        """Update a DID Document."""
        async with ClientSession() as session:
            try:
                async with session.post(
                    self.DID_REGISTRAR_BASE_URL + "update",
                    json=options.model_dump(exclude_none=True),
                ) as response:
                    try:
                        res = await response.json()
                    except Exception:
                        raise CheqdDIDRegistrarError(
                            "cheqd: did-registrar: update: Unable to parse JSON"
                        )
                    if not res:
                        raise CheqdDIDRegistrarError(
                            "cheqd: did-registrar: update: Response is None."
                        )

                    return DidResponse(**res)
            except (ValidationError, AttributeError):
                raise CheqdDIDRegistrarError(
                    "cheqd: did-registrar: update: Response Format is invalid"
                )
            except Exception:
                raise

    async def deactivate(
        self, options: DidDeactivateRequestOptions | SubmitSignatureOptions
    ) -> DidResponse:
        """Deactivate a DID Document."""
        async with ClientSession() as session:
            try:
                async with session.post(
                    self.DID_REGISTRAR_BASE_URL + "deactivate",
                    json=options.model_dump(exclude_none=True),
                ) as response:
                    try:
                        res = await response.json()
                    except Exception:
                        raise CheqdDIDRegistrarError(
                            "cheqd: did-registrar: deactivate: Unable to parse JSON"
                        )
                    if not res:
                        raise CheqdDIDRegistrarError(
                            "cheqd: did-registrar: create_resource: Response is None."
                        )

                    return DidResponse(**res)
            except (ValidationError, AttributeError):
                raise CheqdDIDRegistrarError(
                    "cheqd: did-registrar: deactivate: Response Format is invalid"
                )
            except Exception:
                raise

    async def create_resource(
        self, options: ResourceCreateRequestOptions | SubmitSignatureOptions
    ) -> ResourceResponse:
        """Create a DID Linked Resource."""
        async with ClientSession() as session:
            try:
                async with session.post(
                    self.DID_REGISTRAR_BASE_URL + "createResource",
                    json=options.model_dump(exclude_none=True),
                ) as response:
                    try:
                        res = await response.json()
                    except Exception:
                        raise CheqdDIDRegistrarError(
                            "cheqd: did-registrar: create_resource: Unable to parse JSON"
                        )
                    if not res:
                        raise CheqdDIDRegistrarError(
                            "cheqd: did-registrar: create_resource: Response is None."
                        )

                    return ResourceResponse(**res)
            except (ValidationError, AttributeError):
                raise CheqdDIDRegistrarError(
                    "cheqd: did-registrar: create_resource: Response Format is invalid"
                )
            except Exception:
                raise

    async def update_resource(
        self, options: ResourceUpdateRequestOptions | SubmitSignatureOptions
    ) -> ResourceResponse:
        """Update a DID Linked Resource."""
        async with ClientSession() as session:
            try:
                async with session.post(
                    self.DID_REGISTRAR_BASE_URL + "updateResource",
                    json=options.model_dump(exclude_none=True),
                ) as response:
                    try:
                        res = await response.json()
                    except Exception:
                        raise CheqdDIDRegistrarError(
                            "cheqd: did-registrar: update_resource: Unable to parse JSON"
                        )
                    if not res:
                        raise CheqdDIDRegistrarError(
                            "cheqd: did-registrar: update_resource: Response is None."
                        )

                    return ResourceResponse(**res)
            except (ValidationError, AttributeError):
                raise CheqdDIDRegistrarError(
                    "cheqd: did-registrar: update_resource: Response Format is invalid"
                )
            except Exception:
                raise

    async def deactivate_resource(self, options: dict) -> dict:
        """Deactivate a DID Linked Resource."""
        raise NotImplementedError("This method will not be implemented for did:cheqd.")
