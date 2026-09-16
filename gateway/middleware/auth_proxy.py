"""Reverse proxy middleware and request forwarding with Passkey session enforcement."""

import logging
from collections.abc import Callable
from typing import Any

import httpx
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from gateway.config import settings
from gateway.crypto.tokens import extract_token_from_request, verify_session_token

logger = logging.getLogger("gateway.middleware.auth_proxy")


async def proxy_upstream_request(
    request: Request,
    subpath: str,
    session_payload: dict[str, Any],
) -> Response:
    """Forward authenticated client request to upstream backend service."""
    target_url = f"{settings.UPSTREAM_URL.rstrip('/')}/{subpath.lstrip('/')}"

    # Query parameters
    if request.url.query:
        target_url = f"{target_url}?{request.url.query}"

    # Filter incoming headers and inject authenticated identity assertions
    excluded_headers = {"host", "content-length", "cookie", "authorization"}
    forward_headers = {
        k: v for k, v in request.headers.items() if k.lower() not in excluded_headers
    }
    forward_headers.update({
        "X-Authenticated-User": session_payload.get("sub", ""),
        "X-User-Id": session_payload.get("uid", ""),
        "X-Passkey-Credential-Id": session_payload.get("cid", ""),
        "X-User-Verified": str(session_payload.get("uv", False)).lower(),
        "X-Auth-Time": str(session_payload.get("auth_time", 0)),
        "X-Forwarded-For": request.client.host if request.client else "127.0.0.1",
        "X-Forwarded-Proto": request.url.scheme,
    })

    # Read request body
    body = await request.body()

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            upstream_resp = await client.request(
                method=request.method,
                url=target_url,
                headers=forward_headers,
                content=body,
            )

            # Build response back to caller
            response_headers = {
                k: v for k, v in upstream_resp.headers.items()
                if k.lower() not in {"content-encoding", "transfer-encoding", "content-length"}
            }

            return Response(
                content=upstream_resp.content,
                status_code=upstream_resp.status_code,
                headers=response_headers,
                media_type=upstream_resp.headers.get("content-type"),
            )
    except httpx.RequestError as exc:
        logger.error(f"Error connecting to upstream service at {target_url}: {exc}")
        return JSONResponse(
            status_code=502,
            content={
                "error": "bad_gateway",
                "message": f"Could not connect to upstream service: {exc}",
                "target_url": target_url,
            },
        )


class AuthProxyMiddleware(BaseHTTPMiddleware):
    """Starlette middleware intercepting protected upstream requests."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        path = request.url.path

        # Determine if path requires passkey session protection
        is_upstream = path.startswith("/upstream")
        is_protected_api = path.startswith("/api/protected")

        if not (is_upstream or is_protected_api):
            # Pass through public routes (static files, /api/auth/*, etc.)
            return await call_next(request)

        token = extract_token_from_request(request)
        if not token:
            logger.warning(f"Unauthorized access attempt to {path} without session token.")
            return JSONResponse(
                status_code=401,
                content={
                    "error": "unauthorized",
                    "message": "Authentication required. Please authenticate with your WebAuthn passkey.",
                },
            )

        payload = verify_session_token(token)
        if not payload:
            logger.warning(f"Unauthorized access attempt to {path} with expired/invalid session token.")
            return JSONResponse(
                status_code=401,
                content={
                    "error": "token_expired",
                    "message": "Session has expired or is invalid. Re-authentication required.",
                },
            )

        # Store session payload in request state for downstream handlers
        request.state.session = payload
        return await call_next(request)
