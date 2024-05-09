"""FastAPI status endpoints for readiness and liveness checks."""

import logging

import nest_asyncio
import uvicorn
from fastapi import APIRouter, Depends, HTTPException, Security
from fastapi.security.api_key import APIKeyHeader

nest_asyncio.apply()
router = APIRouter()
API_KEY_NAME = "access_token"
X_API_KEY = APIKeyHeader(name=API_KEY_NAME, auto_error=False)


async def get_api_key(x_api_key: str = Security(X_API_KEY)):
    """Extract and authenticate Header API_KEY."""
    if x_api_key == API_KEY:
        return x_api_key
    else:
        raise HTTPException(status_code=403, detail="Could not validate key")


async def start_status_endpoints_server(api_host, api_port, api_key, handlers):
    """Start the FastAPI status server."""
    logging.info(f"Starting FastAPI service: http://{api_host}:{api_port}")
    global API_KEY
    API_KEY = api_key
    global handler_list
    handler_list = handlers
    uvicorn.run(router, host=api_host, port=int(api_port))


@router.get("/status/ready")
def status_ready(api_key: str = Depends(get_api_key)):
    """Request handler for readiness check."""
    for handler in handler_list:
        if not handler.ready:
            return {"ready": False}
    return {"ready": True}


@router.get("/status/live")
async def status_live(api_key: str = Depends(get_api_key)):
    """Request handler for liveliness check."""
    for handler in handler_list:
        if not await handler.is_running():
            return {"alive": False}
    return {"alive": True}
