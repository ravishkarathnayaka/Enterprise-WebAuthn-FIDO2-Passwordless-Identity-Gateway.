# ADR-001: Monotonic Signature Counter Anti-Replay Verification

## Status
**Accepted** (2026-09-23)

## Context
In high-security enterprise environments, adversaries may attempt to bypass FIDO2 hardware protections by:
1. Cloning virtualized or software-backed authenticator instances across multiple hosts.
2. Intercepting authenticator responses over hostile network segments and attempting assertion replays.
3. Exploiting hardware key backup or extraction vulnerabilities to duplicate key material.

The W3C WebAuthn Level 3 specification (Section 7.2: Verifying an Authentication Assertion) defines an explicit signature counter check mechanism:
> *"If the signature counter value auth_data.counter is greater than 0, or if stored sign_count was greater than 0, compare auth_data.counter to stored sign_count. If auth_data.counter is less than or equal to stored sign_count, this is a potential indicator of a cloned authenticator or replay attack."*

## Decision
We implement a zero-trust, strict monotonic signature counter verification layer in `gateway/crypto/counter_verifier.py`:

```python
def verify_signature_counter(stored_sign_count: int, incoming_sign_count: int) -> int:
    # If the authenticator maintains a monotonic counter, ensure it has incremented
    if stored_sign_count > 0 and incoming_sign_count <= stored_sign_count:
        raise CounterReplayError(
            f"Signature counter violation: received {incoming_sign_count} <= stored {stored_sign_count}"
        )
    return max(stored_sign_count, incoming_sign_count)
```

### Key Rules:
1. **Strict Monotonicity**: When `stored_sign_count > 0`, any incoming counter that is less than or equal to the stored count triggers an immediate `CounterReplayError`.
2. **Zero-Counter Handling**: Authenticators that do not support hardware counters (or platform passkeys implementing synced credentials) report `sign_count = 0`. These pass without error to preserve cross-platform compatibility.
3. **Atomic Persistence**: Successful assertions immediately write the new counter value to persistent storage (`update_credential_sign_count`), ensuring subsequent concurrent or replayed requests are rejected.
4. **Immediate Alerting**: Violations trigger a CEF `AUTH_REPLAY_ATTACK` security audit event (severity 9) and increment `webauthn_counter_replay_violations_total`.

## Consequences

### Positive
- **Deterministic Clone Detection**: Duplicated hardware or software credentials cannot sign requests without causing a counter desynchronization, immediately alerting security operations.
- **Standards Conformance**: 100% compliant with W3C WebAuthn Section 7.2 verification guidelines.
- **Fast Rejection**: Assertions failing counter checks are aborted prior to upstream proxy routing, saving downstream compute.

### Negative / Trade-offs
- **Multi-Device Synced Passkeys**: Providers syncing passkeys across multiple devices without continuous cloud counter sync may trigger false-positive replays if counters desynchronize. In enterprise deployments, roaming hardware security keys (YubiKey, Titan) are prioritized.
