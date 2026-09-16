"""Unit tests ensuring replay attacks with cloned, frozen, or decremented counters are rejected."""

from unittest.mock import patch

import pytest
from webauthn.authentication.verify_authentication_response import (
    VerifiedAuthentication,
)
from webauthn.helpers import bytes_to_base64url
from webauthn.helpers.exceptions import InvalidAuthenticationResponse

from gateway.crypto.authentication import (
    CounterReplayError,
    verify_authentication,
)
from gateway.storage.database import Credential

VALID_CHALLENGE = bytes_to_base64url(b"valid-crypto-challenge-nonce-32")


@pytest.fixture
def mock_credential():
    return Credential(
        id="sample-cred-id-abc-123",
        user_id="user-123",
        public_key=b"public-key-cose-bytes",
        sign_count=10,
    )


def test_monotonically_increasing_counter_succeeds(mock_credential):
    """Assertion with higher counter (10 -> 11) must succeed."""
    mock_verified = VerifiedAuthentication(
        credential_id=b"sample-cred-id-abc-123",
        new_sign_count=11,
        credential_device_type="single_device",
        credential_backed_up=False,
        user_verified=True,
    )

    with patch("gateway.crypto.authentication.webauthn.verify_authentication_response", return_value=mock_verified):
        result = verify_authentication(
            authentication_credential_dict={"id": mock_credential.id, "response": {}},
            expected_challenge=VALID_CHALLENGE,
            credential=mock_credential,
        )

        assert result["new_sign_count"] == 11
        assert result["user_verified"] is True


def test_replayed_counter_raises_counter_replay_error(mock_credential):
    """Assertion with equal counter (10 -> 10) indicates replay attack and MUST be rejected."""
    error_msg = "Response sign count of 10 was not greater than current count of 10"

    with patch(
        "gateway.crypto.authentication.webauthn.verify_authentication_response",
        side_effect=InvalidAuthenticationResponse(error_msg),
    ):
        with pytest.raises(CounterReplayError) as exc_info:
            verify_authentication(
                authentication_credential_dict={"id": mock_credential.id, "response": {}},
                expected_challenge=VALID_CHALLENGE,
                credential=mock_credential,
            )

        assert exc_info.value.stored_counter == 10
        assert exc_info.value.received_counter == 10
        assert "Cloned authenticator or replay attack detected" in str(exc_info.value)


def test_decremented_counter_cloning_attack_rejected(mock_credential):
    """Assertion with lower counter (10 -> 5) indicates an authenticator clone and MUST be rejected."""
    error_msg = "Response sign count of 5 was not greater than current count of 10"

    with patch(
        "gateway.crypto.authentication.webauthn.verify_authentication_response",
        side_effect=InvalidAuthenticationResponse(error_msg),
    ):
        with pytest.raises(CounterReplayError) as exc_info:
            verify_authentication(
                authentication_credential_dict={"id": mock_credential.id, "response": {}},
                expected_challenge=VALID_CHALLENGE,
                credential=mock_credential,
            )

        assert exc_info.value.stored_counter == 10
        assert exc_info.value.received_counter == 5


def test_unrelated_authentication_error_passes_through(mock_credential):
    """Invalid signatures or origin mismatches should raise standard InvalidAuthenticationResponse."""
    with patch(
        "gateway.crypto.authentication.webauthn.verify_authentication_response",
        side_effect=InvalidAuthenticationResponse("Could not verify authentication signature"),
    ):
        with pytest.raises(InvalidAuthenticationResponse):
            verify_authentication(
                authentication_credential_dict={"id": mock_credential.id, "response": {}},
                expected_challenge=VALID_CHALLENGE,
                credential=mock_credential,
            )
