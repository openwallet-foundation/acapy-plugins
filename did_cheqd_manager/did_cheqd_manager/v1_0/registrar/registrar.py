"""DID Registrar for Cheqd."""

from aiohttp import ClientSession, web


class DidCheqdRegistrar:
    """DID Registrar for Cheqd."""

    DID_REGISTRAR_BASE_URL = "https://did-registrar.cheqd.net/1.0/"

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
                        # print(f"Response Text: {await response.text()}")
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
        print(options)
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
