"""WebAuthn assertion generation, signature validation, and anti-replay counter checks."""

import json
import logging
from typing import Any

import webauthn
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.exceptions import InvalidAuthenticationResponse
from webauthn.helpers.structs import (
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialType,
    UserVerificationRequirement,
)

from gateway.config import settings
from gateway.storage.database import Credential

logger = logging.getLogger("gateway.crypto.authentication")


class CounterReplayError(Exception):
    """Raised when an authenticator signature counter indicates token cloning or replay."""

    def __init__(self, message: str, stored_counter: int, received_counter: int):
        super().__init__(message)
        self.stored_counter = stored_counter
        self.received_counter = received_counter


def generate_authentication_challenge(
    credentials: list[Credential] | None = None,
) -> tuple[dict[str, Any], str]:
    """Generate WebAuthn assertion options.

    If credentials are provided, restrict to them via allowCredentials.
    Otherwise, leave empty to permit discoverable credentials (usernameless passkeys).
    """
    allow_list = []
    if credentials:
        for cred in credentials:
            try:
                cred_bytes = base64url_to_bytes(cred.id)
                allow_list.append(
                    PublicKeyCredentialDescriptor(
                        id=cred_bytes,
                        type=PublicKeyCredentialType.PUBLIC_KEY,
                    )
                )
            except Exception as ex:
                logger.warning(f"Failed parsing credential descriptor {cred.id}: {ex}")

    options = webauthn.generate_authentication_options(
        rp_id=settings.RP_ID,
        allow_credentials=allow_list if allow_list else None,
        user_verification=UserVerificationRequirement.PREFERRED,
        timeout=settings.CHALLENGE_TIMEOUT_SECONDS * 1000,
    )

    options_json_str = webauthn.options_to_json(options)
    options_dict = json.loads(options_json_str)
    raw_challenge = bytes_to_base64url(options.challenge)

    return options_dict, raw_challenge


def verify_authentication(
    authentication_credential_dict: dict[str, Any],
    expected_challenge: str,
    credential: Credential,
    require_user_verification: bool = False,
) -> dict[str, Any]:
    """Validate assertion response, cryptographic signature, and anti-replay counters.

    Raises:
        CounterReplayError: If the signature counter was not incremented (potential cloned key).
        InvalidAuthenticationResponse: If signature, origin, RP ID, or challenge is invalid.
    """
    expected_challenge_bytes = base64url_to_bytes(expected_challenge)
    expected_origin = settings.EXPECTED_ORIGIN

    try:
        verified = webauthn.verify_authentication_response(
            credential=authentication_credential_dict,
            expected_challenge=expected_challenge_bytes,
            expected_rp_id=settings.RP_ID,
            expected_origin=expected_origin,
            credential_public_key=credential.public_key,
            credential_current_sign_count=credential.sign_count,
            require_user_verification=require_user_verification,
        )
    except InvalidAuthenticationResponse as ex:
        # Check if the failure was specifically due to signature counter
        err_msg = str(ex)
        if "sign count" in err_msg.lower() and "was not greater than" in err_msg.lower():
            logger.critical(
                f"[SECURITY ALERT] FIDO2 Counter Replay / Clone Attack detected! "
                f"Credential ID: {credential.id} | "
                f"Stored sign_count: {credential.sign_count} | "
                f"Error: {err_msg}"
            )
            # Parse received sign count if possible
            received_counter = -1
            try:
                # "Response sign count of X was not greater than current count of Y"
                parts = err_msg.split()
                if "count" in parts:
                    idx = parts.index("count")
                    if idx + 2 < len(parts) and parts[idx + 1] == "of":
                        received_counter = int(parts[idx + 2])
            except Exception:
                pass
            raise CounterReplayError(
                f"Cloned authenticator or replay attack detected: {err_msg}",
                stored_counter=credential.sign_count,
                received_counter=received_counter,
            ) from ex
        raise

    logger.info(
        f"WebAuthn assertion verified successfully for Credential ID={credential.id[:16]}... "
        f"Prior Counter={credential.sign_count} -> New Counter={verified.new_sign_count}"
    )

    return {
        "credential_id": bytes_to_base64url(verified.credential_id),
        "new_sign_count": verified.new_sign_count,
        "user_verified": verified.user_verified,
        "credential_device_type": str(verified.credential_device_type),
        "credential_backed_up": verified.credential_backed_up,
    }
