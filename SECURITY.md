# Enterprise Security Policy & Incident Response Runbook

## 1. Security Philosophy & Threat Model

The **Enterprise WebAuthn / FIDO2 Passwordless Identity Gateway** is designed for zero-trust environments where client endpoints and communication networks may be adversarial. The gateway completely eliminates shared secrets (passwords) and symmetric credentials in favor of asymmetric public-key cryptography backed by hardware security enclaves (TPM 2.0, Apple Secure Enclave, YubiKey FIPS tokens).

---

## 2. Supported Versions

| Version | Status | Security Patches |
|---|---|---|
| `1.0.x` | **Current Stable** | :white_check_mark: Supported |
| `< 1.0.0` | Deprecated | :x: Unsupported |

---

## 3. Reporting a Vulnerability

We prioritize responsible disclosure and take all potential security findings seriously.

- **Email**: Send encrypted disclosures to `security@ravishkarathnayaka.internal` (or via GitHub Private Vulnerability Reporting).
- **PGP Key Fingerprint**: `F1D0 2026 E987 43B1 09CA C0DE 8295 1200`
- **Response Timeline**:
  - **Initial Acknowledgement**: Within 24 hours.
  - **Severity Triage & CVSS Assessment**: Within 48 hours.
  - **Remediation & Patch Deployment**: Within 5 business days for Critical (CVSS >= 9.0).

Please include:
1. Proof of concept (PoC) script or detailed reproduction steps.
2. Target environment details (OS, Python version, Relying Party configuration).
3. Any relevant CEF/JSON security audit logs emitted by the gateway.

---

## 4. Incident Response Runbook: Monotonic Counter Replay / Cloned Token

When the gateway's anti-replay counter guard triggers an `AUTH_REPLAY_ATTACK` alert, follow this standardized runbook.

### Step 1: Alert Detection & Triage
1. **Trigger Condition**: An incoming WebAuthn assertion presents `incoming_sign_count <= stored_sign_count` with `stored_sign_count > 0`.
2. **Gateway Autonomous Response**:
   - HTTP `403 Forbidden` returned immediately.
   - Structured CEF alert emitted to SIEM (`device_event_class_id="AUTH_REPLAY_ATTACK"`, severity `9`).
   - Counter violation counter incremented: `webauthn_counter_replay_violations_total`.

### Step 2: Immediate Containment
1. **Revoke Active Sessions**:
   ```bash
   # Add all active session tokens for the affected user to the revocation cache
   curl -X POST https://gateway.internal/api/auth/logout \
     -H "Authorization: Bearer <affected_token>"
   ```
2. **Quarantine Compromised Credential**:
   ```sql
   -- Flag credential as quarantined in database
   UPDATE credentials 
   SET nickname = '[QUARANTINED - CLONE ATTACK] ' || COALESCE(nickname, 'Passkey')
   WHERE id = '<credential_id>';
   ```

### Step 3: Forensic Analysis
1. Extract SIEM logs for the matching `cs1=<credential_id>` over the previous 72 hours.
2. Determine whether the collision was caused by:
   - **Cloned Authenticator**: Key private material duplicated across multiple virtual machines or malicious emulators.
   - **Network MITM Replay**: Intercepted authenticator response re-submitted to gateway.
   - **Flawed Firmware / Synced Passkey**: Multi-device sync providers (iCloud Keychain, Google Password Manager) operating with non-monotonic counter implementations.

### Step 4: Eradication & Re-Enrollment
1. Instruct the employee or identity owner to physically inspect hardware authenticators.
2. Delete the quarantined credential from the gateway (`DELETE /api/credentials/{credential_id}`).
3. Conduct in-person or out-of-band identity verification before approving a new hardware key registration.

---

## 5. Defense-in-Depth Hardening Guidelines

1. **Origin Verification**: Never set `EXPECTED_ORIGIN` to a wildcard (`*`). Always specify exact protocols and FQDNs.
2. **TLS 1.3 Termination**: Ensure edge load balancers terminate TLS 1.3 with strict HSTS (`Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`).
3. **Session Cookie Isolation**: Ensure session cookies retain `HttpOnly; Secure; SameSite=Strict`.
