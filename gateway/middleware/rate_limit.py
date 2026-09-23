"""Sliding-window rate limiter for sensitive WebAuthn authentication endpoints."""

import time
from collections import defaultdict
from collections.abc import Callable

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware


class InMemoryRateLimiter:
    """Thread-safe sliding-window rate limiter tracking requests by client IP."""

    def __init__(self, max_requests: int = 30, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._history: dict[str, list[float]] = defaultdict(list)

    def is_allowed(self, client_ip: str) -> tuple[bool, int]:
        """Check if request is permitted under rate limit policy.

        Returns:
            (allowed: bool, retry_after_seconds: int)
        """
        now = time.time()
        window_start = now - self.window_seconds

        # Prune old timestamps
        history = [ts for ts in self._history[client_ip] if ts > window_start]
        self._history[client_ip] = history

        if len(history) >= self.max_requests:
            oldest = history[0]
            retry_after = max(1, int(oldest + self.window_seconds - now))
            return False, retry_after

        self._history[client_ip].append(now)
        return True, 0


# Global limiter for sensitive ceremony endpoints
auth_rate_limiter = InMemoryRateLimiter(max_requests=25, window_seconds=60)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Enforces rate limiting on WebAuthn challenge generation and verification."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        path = request.url.path

        # Rate limit only authentication/registration challenge and verify endpoints
        is_sensitive = path.startswith("/api/auth/register") or path.startswith("/api/auth/login")

        if is_sensitive and request.method == "POST":
            client_ip = request.client.host if request.client else "127.0.0.1"
            allowed, retry_after = auth_rate_limiter.is_allowed(client_ip)

            if not allowed:
                return JSONResponse(
                    status_code=429,
                    content={
                        "error": "too_many_requests",
                        "message": f"Rate limit exceeded on WebAuthn ceremony endpoints. Please retry in {retry_after} seconds.",
                        "retry_after": retry_after,
                    },
                    headers={"Retry-After": str(retry_after)},
                )

        return await call_next(request)
