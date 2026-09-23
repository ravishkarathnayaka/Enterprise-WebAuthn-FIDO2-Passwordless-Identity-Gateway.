"""Cryptographic handlers for WebAuthn registration, authentication, and JWT tokens."""

from gateway.crypto.audit_logger import SecurityAuditLogger, audit_logger
from gateway.crypto.authentication import (
    CounterReplayError,
    generate_authentication_challenge,
    verify_authentication,
)
from gateway.crypto.registration import (
    generate_registration_challenge,
    verify_registration,
)
from gateway.crypto.tokens import create_session_token, verify_session_token

__all__ = [
    "CounterReplayError",
    "SecurityAuditLogger",
    "audit_logger",
    "create_session_token",
    "generate_authentication_challenge",
    "generate_registration_challenge",
    "verify_authentication",
    "verify_registration",
    "verify_session_token",
]
