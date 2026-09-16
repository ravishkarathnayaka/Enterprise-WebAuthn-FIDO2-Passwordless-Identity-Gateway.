"""WebAuthn Level 3 registration options generation and attestation verification."""

import json
import logging
from typing import Any

import webauthn
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialType,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from gateway.config import settings
from gateway.storage.database import Credential, User

logger = logging.getLogger("gateway.crypto.registration")


def _get_cose_algorithms(algo_ids: list[int]) -> list[COSEAlgorithmIdentifier]:
    cose_map = {
        -7: COSEAlgorithmIdentifier.ECDSA_SHA_256,
        -257: COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
        -8: COSEAlgorithmIdentifier.EDDSA,
    }
    return [cose_map[i] for i in algo_ids if i in cose_map]


def generate_registration_challenge(
    user: User,
    existing_credentials: list[Credential] | None = None,
) -> tuple[dict[str, Any], str]:
    """Generate WebAuthn registration options and raw challenge nonce.

    Returns:
        (options_dict, challenge_str)
    """
    exclude_list = []
    if existing_credentials:
        for cred in existing_credentials:
            try:
                cred_bytes = base64url_to_bytes(cred.id)
                exclude_list.append(
                    PublicKeyCredentialDescriptor(
                        id=cred_bytes,
                        type=PublicKeyCredentialType.PUBLIC_KEY,
                    )
                )
            except Exception as ex:
                logger.warning(f"Failed to parse existing credential id {cred.id}: {ex}")

    algorithms = _get_cose_algorithms(settings.SUPPORTED_COSE_ALGORITHMS)

    # Convert user ID to bytes
    user_id_bytes = user.id.encode("utf-8")

    options = webauthn.generate_registration_options(
        rp_name=settings.RP_NAME,
        rp_id=settings.RP_ID,
        user_id=user_id_bytes,
        user_name=user.username,
        user_display_name=user.display_name or user.username,
        attestation=AttestationConveyancePreference.NONE,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
        supported_pub_key_algs=algorithms,
        exclude_credentials=exclude_list if exclude_list else None,
        timeout=settings.CHALLENGE_TIMEOUT_SECONDS * 1000,
    )

    # options_to_json produces compliant JSON with Base64URL encoded fields
    options_json_str = webauthn.options_to_json(options)
    options_dict = json.loads(options_json_str)
    raw_challenge = bytes_to_base64url(options.challenge)

    return options_dict, raw_challenge


def verify_registration(
    registration_credential_dict: dict[str, Any],
    expected_challenge: str,
) -> dict[str, Any]:
    """Verify incoming registration credential against expected challenge and origin.

    Returns structured verification results including public key bytes, sign count, and AAGUID.
    """
    expected_challenge_bytes = base64url_to_bytes(expected_challenge)
    expected_origin = settings.EXPECTED_ORIGIN

    verified = webauthn.verify_registration_response(
        credential=registration_credential_dict,
        expected_challenge=expected_challenge_bytes,
        expected_rp_id=settings.RP_ID,
        expected_origin=expected_origin,
        require_user_verification=False,
    )

    credential_id_str = bytes_to_base64url(verified.credential_id)
    aaguid_str = str(verified.aaguid) if verified.aaguid else None

    logger.info(
        f"WebAuthn credential verified for ID={credential_id_str[:16]}... "
        f"AAGUID={aaguid_str} SignCount={verified.sign_count}"
    )

    return {
        "credential_id": credential_id_str,
        "public_key": verified.credential_public_key,
        "sign_count": verified.sign_count,
        "aaguid": aaguid_str,
        "user_verified": verified.user_verified,
        "credential_device_type": str(verified.credential_device_type),
        "credential_backed_up": verified.credential_backed_up,
    }
