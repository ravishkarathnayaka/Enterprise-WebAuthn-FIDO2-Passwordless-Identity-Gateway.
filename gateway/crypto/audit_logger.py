"""Structured JSON Security Audit Logger conforming to CEF / SIEM standards."""

import json
import logging
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger("gateway.audit")


class SecurityAuditLogger:
    """Emits structured Common Event Format (CEF) and JSON audit logs for IAM ceremonies."""

    VENDOR = "EnterpriseSecurity"
    PRODUCT = "WebAuthnGateway"
    VERSION = "1.0.0"

    @classmethod
    def emit_event(
        cls,
        event_name: str,
        severity: int,
        user_id: str | None = None,
        username: str | None = None,
        credential_id: str | None = None,
        client_ip: str = "127.0.0.1",
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Record and format structured security audit record."""
        record = {
            "timestamp": datetime.now(UTC).isoformat(),
            "cef_version": "CEF:0",
            "device_vendor": cls.VENDOR,
            "device_product": cls.PRODUCT,
            "device_version": cls.VERSION,
            "device_event_class_id": event_name,
            "name": event_name.replace("_", " ").title(),
            "severity": severity,
            "extension": {
                "suser": username or "anonymous",
                "suid": user_id,
                "src": client_ip,
                "cs1": credential_id,
                "cs1Label": "CredentialID",
                **(metadata or {}),
            },
        }

        cef_string = (
            f"CEF:0|{cls.VENDOR}|{cls.PRODUCT}|{cls.VERSION}|{event_name}|"
            f"{record['name']}|{severity}|"
            f"suser={username or 'anonymous'} src={client_ip} cs1={credential_id or 'none'}"
        )

        log_payload = json.dumps(record)

        if severity >= 8:
            logger.critical(f"[SECURITY_AUDIT_ALERT] {cef_string} | RAW={log_payload}")
        elif severity >= 5:
            logger.warning(f"[SECURITY_AUDIT_WARN] {cef_string} | RAW={log_payload}")
        else:
            logger.info(f"[SECURITY_AUDIT_INFO] {cef_string} | RAW={log_payload}")

        return record


# Global auditor instance
audit_logger = SecurityAuditLogger()
