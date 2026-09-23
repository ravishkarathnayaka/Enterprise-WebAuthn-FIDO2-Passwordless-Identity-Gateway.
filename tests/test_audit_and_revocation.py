"""Security tests for CEF/SIEM audit logging and token revocation blocklist."""

import logging
import time

import pytest

from gateway.crypto.audit_logger import SecurityAuditLogger
from gateway.crypto.token_revocation import TokenRevocationStore


def test_security_audit_logger_cef_format():
    record = SecurityAuditLogger.emit_event(
        event_name="AUTH_REPLAY_ATTACK",
        severity=9,
        user_id="usr_9876",
        username="carol_target",
        credential_id="cred_hardware_abc",
        client_ip="198.51.100.25",
        metadata={"attack_vector": "cloned_yubikey", "recorded_counter": 42},
    )

    assert record["cef_version"] == "CEF:0"
    assert record["device_vendor"] == "EnterpriseSecurity"
    assert record["device_product"] == "WebAuthnGateway"
    assert record["device_event_class_id"] == "AUTH_REPLAY_ATTACK"
    assert record["name"] == "Auth Replay Attack"
    assert record["severity"] == 9

    ext = record["extension"]
    assert ext["suser"] == "carol_target"
    assert ext["suid"] == "usr_9876"
    assert ext["src"] == "198.51.100.25"
    assert ext["cs1"] == "cred_hardware_abc"
    assert ext["attack_vector"] == "cloned_yubikey"
    assert ext["recorded_counter"] == 42


def test_security_audit_logger_severity_routing(caplog):
    with caplog.at_level(logging.DEBUG, logger="gateway.audit"):
        # Critical severity (>= 8)
        SecurityAuditLogger.emit_event("CRITICAL_EVENT", severity=9, username="admin")
        assert any("[SECURITY_AUDIT_ALERT]" in rec.message for rec in caplog.records)

        # Warning severity (5..7)
        caplog.clear()
        SecurityAuditLogger.emit_event("WARNING_EVENT", severity=6, username="user1")
        assert any("[SECURITY_AUDIT_WARN]" in rec.message for rec in caplog.records)

        # Informational severity (< 5)
        caplog.clear()
        SecurityAuditLogger.emit_event("INFO_EVENT", severity=2, username="user2")
        assert any("[SECURITY_AUDIT_INFO]" in rec.message for rec in caplog.records)


@pytest.mark.asyncio
async def test_token_revocation_lifecycle():
    store = TokenRevocationStore()
    sample_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test_payload_123.sig"

    # Initially not revoked
    assert await store.is_revoked(sample_jwt) is False

    # Revoke token
    await store.revoke(sample_jwt, ttl_seconds=300)
    assert await store.is_revoked(sample_jwt) is True

    # Other tokens remain unaffected
    assert await store.is_revoked("unrelated_token_value_abc") is False


@pytest.mark.asyncio
async def test_token_revocation_ttl_expiration(monkeypatch):
    current_time = 5000.0
    monkeypatch.setattr(time, "time", lambda: current_time)

    store = TokenRevocationStore()
    token = "temp_jwt_token_for_ttl_test"

    await store.revoke(token, ttl_seconds=10)
    assert await store.is_revoked(token) is True

    # Advance time beyond TTL
    current_time = 5015.0
    assert await store.is_revoked(token) is False
