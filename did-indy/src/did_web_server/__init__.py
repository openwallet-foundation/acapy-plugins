"""Simple DID Web Server implementation."""

from typing import MutableMapping
from fastapi import Body, FastAPI, Request, HTTPException

app = FastAPI(title="DID Web Server", description="A simple DID Web Server.")

storage: MutableMapping[str, dict] = {}


@app.put("/did/{name}")
async def put_did(request: Request, name: str, document: dict = Body()):
    """Store the DID Document at the named location."""
    document = await request.json()
    storage[name] = document


@app.get("/{name}/did.json")
async def get_did_json(name: str) -> dict:
    """Get the DID Document at the named location."""
    doc = storage.get(name)
    if not doc:
        raise HTTPException(status_code=404, detail="DID Not Found")
    return doc
