"""Unit tests for AAGUID hardware registry and credential management persistence."""

import uuid

import pytest

from gateway.crypto.aaguid_lookup import resolve_aaguid
from gateway.storage.database import (
    delete_credential,
    get_credential_by_id,
    get_credentials_for_user,
    get_or_create_user,
    init_db,
    rename_credential,
    save_credential,
)


def test_resolve_aaguid_known_vendors():
    # Apple Secure Enclave
    apple_meta = resolve_aaguid("ea9b8d66-4d01-1d21-3ce2-b6b47c66d10c")
    assert apple_meta["vendor"] == "Apple Inc."
    assert "Secure Enclave" in apple_meta["model"]
    assert apple_meta["form_factor"] == "platform"

    # YubiKey 5 Series
    yubi_meta = resolve_aaguid("ee5537a5-911a-4c91-881e-9883380b997f")
    assert yubi_meta["vendor"] == "Yubico"
    assert "YubiKey 5" in yubi_meta["model"]
    assert yubi_meta["assurance"] == "L3 - FIPS 140-2 Level 3 Hardware"

    # Microsoft Windows Hello
    ms_meta = resolve_aaguid("08987058-cadc-4b81-b6e1-30de50dcbe96")
    assert ms_meta["vendor"] == "Windows Hello"
    assert "TPM 2.0" in ms_meta["model"]

    # Google Titan
    titan_meta = resolve_aaguid("42358055-680c-4861-a08b-6f29da2d80d5")
    assert titan_meta["vendor"] == "Google"
    assert "Titan" in titan_meta["model"]


def test_resolve_aaguid_fallback_handling():
    # None or empty input defaults to generic passkey
    fallback_none = resolve_aaguid(None)
    assert fallback_none["vendor"] == "Generic Passkey"
    assert fallback_none["form_factor"] == "synced"

    fallback_empty = resolve_aaguid("")
    assert fallback_empty["vendor"] == "Generic Passkey"

    # Unknown GUID should return structured fallback with truncated ID
    unknown = resolve_aaguid("ffffffff-1234-5678-9abc-def012345678")
    assert unknown["vendor"] == "FIDO2 Authenticator"
    assert "ffffffff" in unknown["model"]


@pytest.mark.asyncio
async def test_credential_lifecycle_and_management():
    await init_db()

    # Create test user with unique username
    unique_user = f"user_{uuid.uuid4().hex[:8]}"
    user = await get_or_create_user(unique_user, "Alice Crypto Test")
    assert user.id is not None

    # Register credentials with unique id
    cred_id = f"test_cred_{uuid.uuid4().hex[:12]}"
    raw_key = b"sample_cose_public_key_alice"
    aaguid = "ee5537a5-911a-4c91-881e-9883380b997f"  # YubiKey 5

    saved = await save_credential(
        user_id=user.id,
        credential_id=cred_id,
        public_key=raw_key,
        sign_count=10,
        aaguid=aaguid,
        transports=["usb", "nfc"],
    )
    assert saved.id == cred_id
    assert saved.sign_count == 10
    assert saved.transport_list == ["usb", "nfc"]

    # Retrieve credentials for user
    creds = await get_credentials_for_user(user.id)
    assert any(c.id == cred_id for c in creds)

    # Rename credential
    renamed = await rename_credential(cred_id, user.id, "Personal YubiKey NFC")
    assert renamed is True

    fetched = await get_credential_by_id(cred_id)
    assert fetched is not None
    assert fetched.nickname == "Personal YubiKey NFC"

    # Attempt renaming with wrong user should fail
    renamed_wrong = await rename_credential(cred_id, "other_fake_user_id", "Hacked")
    assert renamed_wrong is False

    # Delete credential
    deleted = await delete_credential(cred_id, user.id)
    assert deleted is True

    # Confirm deletion
    post_delete = await get_credential_by_id(cred_id)
    assert post_delete is None
