"""DID Registrar for Cheqd."""

from aiohttp import ClientSession, web

from ..did.base import BaseDIDRegistrar


class CheqdDIDRegistrar(BaseDIDRegistrar):
    """DID Registrar implementation for did:cheqd."""

    DID_REGISTRAR_BASE_URL = "http://localhost:3000/1.0/"

    def __init__(self, registrar_url: str = None) -> None:
        """Initialize the Cheqd Registrar."""
        super().__init__()
        if registrar_url:
            self.DID_REGISTRAR_BASE_URL = registrar_url

    async def generate_did_doc(self, network: str, public_key_hex: str) -> dict | None:
        """Generates a did_document with the provided params."""
        async with ClientSession() as session:
            try:
                async with session.get(
                    self.DID_REGISTRAR_BASE_URL + "did-document",
                    params={
                        "verificationMethod": "Ed25519VerificationKey2020",
                        "methodSpecificIdAlgo": "uuid",
                        "network": network,
                        "publicKeyHex": public_key_hex,
                    },
                ) as response:
                    if response.status == 200:
                        return await response.json()
                    else:
                        raise Exception(response)
            except Exception:
                raise

    async def create(self, options: dict) -> dict | None:
        """Create a DID Document."""
        async with ClientSession() as session:
            try:
                async with session.post(
                    self.DID_REGISTRAR_BASE_URL + "create", json=options
                ) as response:
                    return await response.json()
            except Exception:
                raise

    async def update(self, options: dict) -> dict:
        """Update a DID Document."""
        async with ClientSession() as session:
            try:
                async with session.post(
                    self.DID_REGISTRAR_BASE_URL + "update", json=options
                ) as response:
                    return await response.json()
            except Exception:
                raise

    async def deactivate(self, options: dict) -> dict:
        """Deactivate a DID Document."""
        async with ClientSession() as session:
            try:
                async with session.post(
                    self.DID_REGISTRAR_BASE_URL + "deactivate", json=options
                ) as response:
                    return await response.json()
            except Exception:
                raise

    async def create_resource(self, did: str, options: dict) -> dict:
        """Create a DID Linked Resource."""
        async with ClientSession() as session:
            try:
                async with session.post(
                    self.DID_REGISTRAR_BASE_URL + did + "/create-resource", json=options
                ) as response:
                    if response.status == 200 or response.status == 201:
                        return await response.json()
                    else:
                        raise web.HTTPInternalServerError()
            except Exception:
                raise

    async def update_resource(self, did: str, options: dict) -> dict:
        """Update a DID Linked Resource."""
        raise NotImplementedError("This method has not been implemented yet.")

    async def deactivate_resource(self, did: str, options: dict) -> dict:
        """Deactivate a DID Linked Resource."""
        raise NotImplementedError("This method will not be implemented for did:cheqd.")
