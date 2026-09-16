"""Session token management: signed short-lived JWTs, step-up auth validation, and cookie handling."""

import time
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from fastapi import Request, Response

from gateway.config import settings


def create_session_token(
    user_id: str,
    username: str,
    credential_id: str,
    user_verified: bool = False,
    expires_delta: timedelta | None = None,
) -> str:
    """Generate a cryptographically signed JWT session token."""
    now = datetime.now(UTC)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.SESSION_EXPIRATION_MINUTES)

    auth_timestamp = int(now.timestamp())

    payload = {
        "sub": username,
        "uid": user_id,
        "cid": credential_id,
        "uv": user_verified,
        "auth_time": auth_timestamp,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    }

    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def verify_session_token(token: str) -> dict[str, Any] | None:
    """Decode and verify JWT signature and expiration.

    Returns token payload dict or None if invalid/expired.
    """
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
            options={"require": ["exp", "sub", "uid", "auth_time"]},
        )
        return payload
    except (jwt.PyJWTError, ValueError):
        return None


def is_step_up_valid(token_payload: dict[str, Any], max_age_seconds: int | None = None) -> bool:
    """Check if the session authentication timestamp is recent enough for step-up auth."""
    limit = max_age_seconds or settings.STEP_UP_MAX_AGE_SECONDS
    auth_time = token_payload.get("auth_time")
    if not auth_time:
        return False

    current_time = int(time.time())
    age = current_time - int(auth_time)
    return age <= limit


def extract_token_from_request(request: Request) -> str | None:
    """Extract session token from HttpOnly cookie or Authorization header."""
    # 1. Check HttpOnly session cookie
    cookie_token = request.cookies.get(settings.COOKIE_NAME)
    if cookie_token:
        return cookie_token

    # 2. Check Authorization Bearer header
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        return auth_header[7:].strip()

    return None


def set_session_cookie(response: Response, token: str) -> None:
    """Set secure HttpOnly cookie for session token."""
    max_age = settings.SESSION_EXPIRATION_MINUTES * 60
    response.set_cookie(
        key=settings.COOKIE_NAME,
        value=token,
        max_age=max_age,
        httponly=True,
        samesite="lax",
        secure=False,  # Set to True in HTTPS/production; False for localhost HTTP development
        path="/",
    )


def clear_session_cookie(response: Response) -> None:
    """Invalidate session cookie on logout."""
    response.delete_cookie(
        key=settings.COOKIE_NAME,
        path="/",
        httponly=True,
        samesite="lax",
    )
