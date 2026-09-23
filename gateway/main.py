"""Enterprise WebAuthn / FIDO2 Passwordless Identity Gateway Application."""

import base64
import json
import logging
import os
import time
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from gateway.config import settings
from gateway.crypto.aaguid_lookup import resolve_aaguid
from gateway.crypto.audit_logger import audit_logger
from gateway.crypto.authentication import (
    CounterReplayError,
    generate_authentication_challenge,
    verify_authentication,
)
from gateway.crypto.registration import (
    generate_registration_challenge,
    verify_registration,
)
from gateway.crypto.tokens import (
    clear_session_cookie,
    create_session_token,
    extract_token_from_request,
    is_step_up_valid,
    set_session_cookie,
    verify_session_token,
)
from gateway.middleware.auth_proxy import AuthProxyMiddleware, proxy_upstream_request
from gateway.middleware.rate_limit import RateLimitMiddleware
from gateway.middleware.telemetry import TelemetryMiddleware, metrics
from gateway.storage.challenge_store import challenge_store
from gateway.storage.database import (
    delete_credential,
    get_credential_by_id,
    get_credentials_for_user,
    get_or_create_user,
    get_user_by_id,
    get_user_by_username,
    init_db,
    rename_credential,
    save_credential,
    update_credential_sign_count,
)

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s]: %(message)s",
)
logger = logging.getLogger("gateway.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown events."""
    logger.info("Starting Enterprise WebAuthn Identity Gateway...")
    await init_db()
    logger.info("Database initialized.")
    await challenge_store.initialize()
    logger.info(f"Relying Party: ID={settings.RP_ID}, Name='{settings.RP_NAME}'")
    yield
    logger.info("Shutting down Enterprise WebAuthn Identity Gateway.")


app = FastAPI(
    title="Enterprise WebAuthn Identity Gateway",
    description="FIDO2 / WebAuthn Level 3 Relying Party & Reverse Proxy Gateway",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.EXPECTED_ORIGIN if isinstance(settings.EXPECTED_ORIGIN, list) else [settings.EXPECTED_ORIGIN],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Reverse Proxy & Auth Middleware
app.add_middleware(AuthProxyMiddleware)
app.add_middleware(TelemetryMiddleware)
app.add_middleware(RateLimitMiddleware)

# Static files directory
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


# Pydantic Request Models
class RegisterOptionsRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=100)
    displayName: str | None = Field(None, max_length=150)


class RegisterVerifyRequest(BaseModel):
    credential: dict[str, Any]
    username: str | None = None
    challenge: str | None = None


class LoginOptionsRequest(BaseModel):
    username: str | None = None


class LoginVerifyRequest(BaseModel):
    credential: dict[str, Any]
    challenge: str | None = None


class TransferRequest(BaseModel):
    recipient: str = "Corporate Escrow Acct #8829"
    amount: float = 50000.00
    description: str | None = "High-Value Wire Transfer"


class RenameCredentialRequest(BaseModel):
    nickname: str = Field(..., min_length=1, max_length=100)


# Authentication Dependency Helper
async def get_current_session(request: Request) -> dict[str, Any]:
    """Dependency ensuring caller possesses a valid session token."""
    token = extract_token_from_request(request)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session token required. Authenticate with a passkey.",
        )
    payload = verify_session_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired or invalid.",
        )
    return payload


# Helper to parse challenge from clientDataJSON
def extract_challenge_from_client_data(client_data_json_b64: str) -> str | None:
    try:
        # Pad base64url if needed
        padding = "=" * ((4 - len(client_data_json_b64) % 4) % 4)
        raw_bytes = base64.urlsafe_b64decode(client_data_json_b64 + padding)
        data = json.loads(raw_bytes.decode("utf-8"))
        return data.get("challenge")
    except Exception:
        return None


# --------------------------------------------------------------------------
# Gateway Public & Health Endpoints
# --------------------------------------------------------------------------

@app.get("/")
async def root():
    """Serve Passkey Authentication Gateway Web Portal."""
    index_file = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return JSONResponse({
        "name": "Enterprise WebAuthn / FIDO2 Identity Gateway",
        "status": "online",
        "rp_id": settings.RP_ID,
    })


@app.get("/health")
async def health_check():
    """System health check and relying party configuration info."""
    return {
        "status": "healthy",
        "rp_id": settings.RP_ID,
        "rp_name": settings.RP_NAME,
        "expected_origins": settings.EXPECTED_ORIGIN,
        "redis_configured": bool(settings.REDIS_URL),
        "upstream_target": settings.UPSTREAM_URL,
    }


@app.get("/metrics", response_class=PlainTextResponse)
async def get_prometheus_metrics():
    """Expose Prometheus telemetry and ceremony performance metrics."""
    return PlainTextResponse(metrics.generate_prometheus_metrics(), media_type="text/plain")


# --------------------------------------------------------------------------
# WebAuthn Registration Ceremony
# --------------------------------------------------------------------------

@app.post("/api/auth/register/options")
async def registration_options(req: RegisterOptionsRequest):
    """Generate WebAuthn Level 3 PublicKeyCredentialCreationOptions."""
    username = req.username.strip()
    user = await get_or_create_user(username, req.displayName)
    existing_credentials = await get_credentials_for_user(user.id)

    options_dict, challenge_str = generate_registration_challenge(user, existing_credentials)

    # Cache challenge transiently with strict TTL
    challenge_key = f"reg:{challenge_str}"
    await challenge_store.save_challenge(
        challenge_key=challenge_key,
        challenge=challenge_str,
        user_id=user.id,
        extra_data={"username": user.username},
        ttl_seconds=settings.CHALLENGE_TIMEOUT_SECONDS,
    )

    logger.info(f"Generated registration options for user='{username}' with challenge key={challenge_key[:16]}...")
    return {
        "options": options_dict,
        "challenge": challenge_str,
    }


@app.post("/api/auth/register/verify")
async def registration_verify(req: RegisterVerifyRequest):
    """Verify WebAuthn attestation response and persist new cryptographic credential."""
    cred_data = req.credential
    response_data = cred_data.get("response", {})
    client_data_b64 = response_data.get("clientDataJSON", "")

    # Extract challenge from clientDataJSON or explicit param
    challenge_str = req.challenge or extract_challenge_from_client_data(client_data_b64)
    if not challenge_str:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Could not resolve challenge from registration response.",
        )

    # Atomically consume challenge nonce to prevent replay
    challenge_key = f"reg:{challenge_str}"
    cached_challenge = await challenge_store.consume_challenge(challenge_key)
    if not cached_challenge:
        logger.warning(f"Registration challenge {challenge_key[:16]}... expired or replayed.")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Registration challenge expired or already consumed.",
        )

    # Verify cryptographic attestation statement and origin
    try:
        verified = verify_registration(cred_data, challenge_str)
    except Exception as ex:
        logger.error(f"WebAuthn registration verification failed: {ex}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Registration verification failed: {ex!s}",
        )

    # Retrieve user ID associated with the registration ceremony
    user_id = cached_challenge.get("user_id")
    if not user_id and req.username:
        user = await get_user_by_username(req.username)
        if user:
            user_id = user.id

    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unable to correlate credential with user entity.",
        )

    # Transports (e.g. ['internal', 'usb', 'nfc'])
    transports = response_data.get("transports", [])

    # Persist credential
    saved_cred = await save_credential(
        user_id=user_id,
        credential_id=verified["credential_id"],
        public_key=verified["public_key"],
        sign_count=verified["sign_count"],
        aaguid=verified["aaguid"],
        transports=transports,
    )

    logger.info(f"Registered new Passkey for user_id={user_id}, cred_id={saved_cred.id[:16]}...")
    metrics.record_registration()
    audit_logger.emit_event(
        event_name="PASSKEY_REGISTRATION_SUCCESS",
        severity=3,
        user_id=user_id,
        credential_id=saved_cred.id,
        metadata={"aaguid": verified["aaguid"], "user_verified": verified["user_verified"]},
    )

    return {
        "status": "ok",
        "message": "Passkey registered successfully.",
        "credential_id": saved_cred.id,
        "aaguid": verified["aaguid"],
        "user_verified": verified["user_verified"],
    }


# --------------------------------------------------------------------------
# WebAuthn Authentication (Login) Ceremony
# --------------------------------------------------------------------------

@app.post("/api/auth/login/options")
async def login_options(req: LoginOptionsRequest):
    """Generate WebAuthn Level 3 PublicKeyCredentialRequestOptions."""
    credentials = None
    if req.username:
        user = await get_user_by_username(req.username.strip())
        if user:
            credentials = await get_credentials_for_user(user.id)

    options_dict, challenge_str = generate_authentication_challenge(credentials)

    challenge_key = f"auth:{challenge_str}"
    await challenge_store.save_challenge(
        challenge_key=challenge_key,
        challenge=challenge_str,
        extra_data={"username": req.username} if req.username else {},
        ttl_seconds=settings.CHALLENGE_TIMEOUT_SECONDS,
    )

    logger.info(f"Generated authentication options with challenge key={challenge_key[:16]}...")
    return {
        "options": options_dict,
        "challenge": challenge_str,
    }


@app.post("/api/auth/login/verify")
async def login_verify(req: LoginVerifyRequest, response: Response):
    """Verify WebAuthn assertion signature, enforce anti-replay counter checks, and issue session."""
    cred_data = req.credential
    cred_id = cred_data.get("id")
    if not cred_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing credential ID in assertion response.",
        )

    # Retrieve stored public key and counter
    stored_cred = await get_credential_by_id(cred_id)
    if not stored_cred:
        logger.warning(f"Authentication attempt with unknown credential ID: {cred_id[:16]}...")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Credential not recognized by this Relying Party.",
        )

    # Extract challenge
    response_data = cred_data.get("response", {})
    client_data_b64 = response_data.get("clientDataJSON", "")
    challenge_str = req.challenge or extract_challenge_from_client_data(client_data_b64)

    if not challenge_str:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Could not resolve challenge from assertion response.",
        )

    # Atomically consume challenge nonce
    challenge_key = f"auth:{challenge_str}"
    cached_challenge = await challenge_store.consume_challenge(challenge_key)
    if not cached_challenge:
        logger.warning(f"Authentication challenge {challenge_key[:16]}... expired or replayed.")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Authentication challenge expired or already consumed.",
        )

    # Validate assertion signature and enforce signature counter checks
    try:
        verified = verify_authentication(
            authentication_credential_dict=cred_data,
            expected_challenge=challenge_str,
            credential=stored_cred,
        )
    except CounterReplayError as replay_err:
        logger.critical(
            f"[CRITICAL SECURITY BREACH] Anti-replay counter violation for Credential ID={stored_cred.id}: {replay_err}"
        )
        metrics.record_counter_replay_violation()
        metrics.record_authentication("replay_detected")
        audit_logger.emit_event(
            event_name="PASSKEY_COUNTER_REPLAY_DETECTED",
            severity=10,
            user_id=stored_cred.user_id,
            credential_id=stored_cred.id,
            metadata={
                "stored_counter": replay_err.stored_counter,
                "received_counter": replay_err.received_counter,
                "alert": "POTENTIAL_TOKEN_CLONING",
            },
        )
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={
                "error": "counter_replay_detected",
                "message": "Potential cloned authenticator or replay attack detected. Signature counter not incremented.",
                "stored_counter": replay_err.stored_counter,
                "received_counter": replay_err.received_counter,
            },
        )
    except Exception as ex:
        logger.error(f"Assertion verification error: {ex}")
        metrics.record_authentication("failure")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Assertion verification failed: {ex!s}",
        )

    # Update stored sign counter
    await update_credential_sign_count(stored_cred.id, verified["new_sign_count"])
    metrics.record_authentication("success")

    # Retrieve user
    user = await get_user_by_id(stored_cred.user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User associated with credential not found.",
        )

    audit_logger.emit_event(
        event_name="PASSKEY_AUTHENTICATION_SUCCESS",
        severity=2,
        user_id=user.id,
        username=user.username,
        credential_id=stored_cred.id,
        metadata={"sign_count": verified["new_sign_count"], "user_verified": verified["user_verified"]},
    )

    # Issue short-lived cryptographically signed session token
    token = create_session_token(
        user_id=user.id,
        username=user.username,
        credential_id=stored_cred.id,
        user_verified=verified["user_verified"],
    )

    # Set secure HttpOnly session cookie
    set_session_cookie(response, token)

    logger.info(
        f"Authenticated user='{user.username}' via Passkey={stored_cred.id[:16]}... "
        f"SignCount={verified['new_sign_count']}, UV={verified['user_verified']}"
    )

    return {
        "status": "ok",
        "message": "Passkey authentication successful.",
        "token": token,
        "user": {
            "id": user.id,
            "username": user.username,
            "displayName": user.display_name,
        },
        "session": {
            "sign_count": verified["new_sign_count"],
            "user_verified": verified["user_verified"],
            "auth_time": int(time.time()),
        },
    }


# --------------------------------------------------------------------------
# Session, Step-Up Auth, and Reverse Proxy Handlers
# --------------------------------------------------------------------------

@app.post("/api/auth/logout")
async def logout(response: Response):
    """Invalidate session cookie."""
    clear_session_cookie(response)
    return {"status": "ok", "message": "Logged out successfully."}


@app.get("/api/auth/me")
async def get_current_user_profile(session: dict[str, Any] = Depends(get_current_session)):
    """Retrieve currently authenticated user profile, passkeys, and session state."""
    user = await get_user_by_id(session["uid"])
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    credentials = await get_credentials_for_user(user.id)

    auth_time = session.get("auth_time", 0)
    current_time = int(time.time())
    step_up_remaining = max(0, settings.STEP_UP_MAX_AGE_SECONDS - (current_time - auth_time))

    return {
        "user": {
            "id": user.id,
            "username": user.username,
            "displayName": user.display_name,
        },
        "session": {
            "credential_id": session.get("cid"),
            "user_verified": session.get("uv", False),
            "auth_time": auth_time,
            "step_up_valid": is_step_up_valid(session),
            "step_up_remaining_seconds": step_up_remaining,
        },
        "credentials": [
            {
                "id": c.id,
                "nickname": c.nickname,
                "sign_count": c.sign_count,
                "aaguid": c.aaguid,
                "metadata": resolve_aaguid(c.aaguid),
                "transports": c.transport_list,
                "created_at": c.created_at.isoformat() if c.created_at else None,
                "last_used_at": c.last_used_at.isoformat() if c.last_used_at else None,
            }
            for c in credentials
        ],
    }


@app.get("/api/credentials")
async def list_user_credentials(session: dict[str, Any] = Depends(get_current_session)):
    """Retrieve all registered Passkeys for current user with AAGUID metadata."""
    credentials = await get_credentials_for_user(session["uid"])
    return {
        "status": "ok",
        "credentials": [
            {
                "id": c.id,
                "nickname": c.nickname or resolve_aaguid(c.aaguid)["model"],
                "sign_count": c.sign_count,
                "aaguid": c.aaguid,
                "metadata": resolve_aaguid(c.aaguid),
                "transports": c.transport_list,
                "created_at": c.created_at.isoformat() if c.created_at else None,
                "last_used_at": c.last_used_at.isoformat() if c.last_used_at else None,
            }
            for c in credentials
        ],
    }


@app.patch("/api/credentials/{credential_id}")
async def rename_user_credential(
    credential_id: str,
    req: RenameCredentialRequest,
    session: dict[str, Any] = Depends(get_current_session),
):
    """Update friendly nickname for a specific registered Passkey."""
    success = await rename_credential(credential_id, session["uid"], req.nickname.strip())
    if not success:
        raise HTTPException(status_code=404, detail="Credential not found or unauthorized.")
    return {"status": "ok", "message": "Passkey renamed successfully.", "nickname": req.nickname.strip()}


@app.delete("/api/credentials/{credential_id}")
async def revoke_user_credential(
    credential_id: str,
    session: dict[str, Any] = Depends(get_current_session),
):
    """Revoke and delete a specific registered Passkey."""
    success = await delete_credential(credential_id, session["uid"])
    if not success:
        raise HTTPException(status_code=404, detail="Credential not found or unauthorized.")

    audit_logger.emit_event(
        event_name="PASSKEY_REVOKED",
        severity=5,
        user_id=session["uid"],
        credential_id=credential_id,
        metadata={"action": "USER_INITIATED_REVOCATION"},
    )
    return {"status": "ok", "message": "Passkey revoked successfully."}


@app.post("/api/admin/transfer")
async def perform_step_up_transfer(
    req: TransferRequest,
    session: dict[str, Any] = Depends(get_current_session),
):
    """High-risk financial wire transfer mandating fresh Passkey step-up authentication.

    If the session authentication occurred more than STEP_UP_MAX_AGE_SECONDS (60s) ago,
    a 403 Forbidden step_up_required response is returned.
    """
    if not is_step_up_valid(session, max_age_seconds=settings.STEP_UP_MAX_AGE_SECONDS):
        auth_age = int(time.time()) - session.get("auth_time", 0)
        logger.warning(
            f"Step-up re-authentication required for high-risk transfer by '{session['sub']}' "
            f"(auth age: {auth_age}s > {settings.STEP_UP_MAX_AGE_SECONDS}s)"
        )
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={
                "error": "step_up_required",
                "message": (
                    f"Step-up authentication required: Re-authenticate with your WebAuthn passkey "
                    f"to authorize this transaction. (Session auth age: {auth_age}s; max allowed: {settings.STEP_UP_MAX_AGE_SECONDS}s)"
                ),
                "max_age_seconds": settings.STEP_UP_MAX_AGE_SECONDS,
                "auth_age_seconds": auth_age,
            },
        )

    # Step-up verified! Execute transfer
    logger.info(
        f"[STEP-UP AUTHORIZED] Wire transfer of ${req.amount:,.2f} to {req.recipient} "
        f"authorized by '{session['sub']}' with Passkey {session['cid'][:16]}..."
    )

    return {
        "status": "success",
        "action": "wire_transfer",
        "amount": req.amount,
        "recipient": req.recipient,
        "description": req.description,
        "authorized_by": session["sub"],
        "user_id": session["uid"],
        "passkey_credential_id": session["cid"],
        "user_verified": session.get("uv", False),
        "timestamp": int(time.time()),
    }


@app.api_route("/upstream/{subpath:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def route_upstream(
    subpath: str,
    request: Request,
    session: dict[str, Any] = Depends(get_current_session),
):
    """Reverse proxy authenticated requests to upstream protected microservice."""
    return await proxy_upstream_request(request, subpath, session)
