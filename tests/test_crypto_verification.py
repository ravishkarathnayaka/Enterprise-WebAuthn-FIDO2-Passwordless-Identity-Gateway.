"""Unit tests evaluating raw CBOR/COSE parsing, challenge life-cycle, and JWT security tokens."""

import asyncio
import time

import pytest
from webauthn.helpers.cose import COSEAlgorithmIdentifier

from gateway.config import settings
from gateway.crypto.authentication import generate_authentication_challenge
from gateway.crypto.registration import (
    _get_cose_algorithms,
    generate_registration_challenge,
)
from gateway.crypto.tokens import (
    create_session_token,
    is_step_up_valid,
    verify_session_token,
)
from gateway.storage.challenge_store import ChallengeStore
from gateway.storage.database import Credential, User


@pytest.fixture
def sample_user():
    return User(
        id="a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d",
        username="alice.test@enterprise.internal",
        display_name="Alice Test",
    )


@pytest.fixture
def sample_credential():
    return Credential(
        id="dGVzdC1jcmVkZW50aWFsLWlkLTEyMzQ1Njc4",
        user_id="a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d",
        public_key=b"fake-cose-key-bytes",
        sign_count=5,
    )


def test_cose_algorithms_mapping():
    """Verify supported COSE cryptographic algorithms match WebAuthn Level 3 specs."""
    algs = _get_cose_algorithms([-7, -257, -8])
    assert COSEAlgorithmIdentifier.ECDSA_SHA_256 in algs
    assert COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256 in algs
    assert COSEAlgorithmIdentifier.EDDSA in algs


def test_registration_challenge_generation(sample_user, sample_credential):
    """Test generating registration options conforms to WebAuthn specification."""
    options, challenge = generate_registration_challenge(sample_user, [sample_credential])

    assert "challenge" in options
    assert options["rp"]["id"] == settings.RP_ID
    assert options["rp"]["name"] == settings.RP_NAME
    assert options["user"]["name"] == sample_user.username
    assert len(challenge) > 20
    assert len(options["pubKeyCredParams"]) >= 2
    # Verify excluded credentials contains our sample credential
    assert "excludeCredentials" in options
    assert len(options["excludeCredentials"]) == 1
    assert options["excludeCredentials"][0]["id"] == sample_credential.id


def test_authentication_challenge_generation(sample_credential):
    """Test generating authentication options with allowCredentials."""
    options, challenge = generate_authentication_challenge([sample_credential])

    assert "challenge" in options
    assert options["rpId"] == settings.RP_ID
    assert len(challenge) > 20
    assert "allowCredentials" in options
    assert len(options["allowCredentials"]) == 1
    assert options["allowCredentials"][0]["id"] == sample_credential.id


def test_authentication_challenge_discoverable_credentials():
    """Test generating options without credentials allows passkey autofill."""
    options, challenge = generate_authentication_challenge(None)
    assert "challenge" in options
    assert options.get("allowCredentials") in (None, [])


def test_session_token_lifecycle():
    """Test JWT creation, cryptographic verification, and payload extraction."""
    user_id = "user-uuid-1234"
    username = "carol@enterprise.corp"
    cred_id = "cred-xyz-987"

    token = create_session_token(
        user_id=user_id,
        username=username,
        credential_id=cred_id,
        user_verified=True,
    )

    payload = verify_session_token(token)
    assert payload is not None
    assert payload["sub"] == username
    assert payload["uid"] == user_id
    assert payload["cid"] == cred_id
    assert payload["uv"] is True
    assert "auth_time" in payload
    assert payload["exp"] > time.time()


def test_session_token_tampering_rejected():
    """Verify tampered JWT tokens fail signature validation."""
    token = create_session_token("u1", "alice", "c1")
    tampered = token[:-4] + "abcd"
    assert verify_session_token(tampered) is None


def test_step_up_validation_window():
    """Verify step-up authorization window adheres to max age policy."""
    now = int(time.time())

    # Fresh token (authenticated 10 seconds ago) -> VALID
    valid_payload = {"auth_time": now - 10}
    assert is_step_up_valid(valid_payload, max_age_seconds=60) is True

    # Stale token (authenticated 75 seconds ago) -> INVALID
    stale_payload = {"auth_time": now - 75}
    assert is_step_up_valid(stale_payload, max_age_seconds=60) is False

    # Missing auth_time -> INVALID
    assert is_step_up_valid({}, max_age_seconds=60) is False


@pytest.mark.asyncio
async def test_transient_challenge_store_single_use():
    """Ensure challenge nonces can only be consumed once (anti-replay)."""
    store = ChallengeStore()

    challenge_key = "test:nonce-12345"
    challenge_val = "random-cryptographic-challenge-nonce"

    await store.save_challenge(challenge_key, challenge_val, user_id="user-1", ttl_seconds=5)

    # First consumption: SUCCESS
    result = await store.consume_challenge(challenge_key)
    assert result is not None
    assert result["challenge"] == challenge_val
    assert result["user_id"] == "user-1"

    # Second consumption: REJECTED (Consumed atomically)
    second_attempt = await store.consume_challenge(challenge_key)
    assert second_attempt is None


@pytest.mark.asyncio
async def test_transient_challenge_store_ttl_expiration():
    """Ensure expired challenge nonces cannot be consumed."""
    store = ChallengeStore()
    challenge_key = "test:nonce-expired"

    # Save with 1 second TTL
    await store.save_challenge(challenge_key, "data", ttl_seconds=1)
    await asyncio.sleep(1.2)

    # Should be expired
    assert await store.consume_challenge(challenge_key) is None
