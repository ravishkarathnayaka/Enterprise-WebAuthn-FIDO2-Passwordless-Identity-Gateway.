"""FIDO2 Authenticator Attestation Globally Unique Identifier (AAGUID) lookup registry."""

KNOWN_AAGUIDS: dict[str, dict[str, str]] = {
    # Apple Platform Authenticators
    "00000000-0000-0000-0000-000000000000": {
        "vendor": "FIDO Alliance / Standard",
        "model": "Unspecified FIDO2 Authenticator",
        "assurance": "L1 - Platform / Synced Passkey",
        "form_factor": "platform",
    },
    "ea9b8d66-4d01-1d21-3ce2-b6b47c66d10c": {
        "vendor": "Apple Inc.",
        "model": "Apple Secure Enclave (Touch ID / Face ID)",
        "assurance": "L2 - Hardware Secure Enclave",
        "form_factor": "platform",
    },
    "08987058-cadc-4b81-b6e1-30de50dcbe96": {
        "vendor": "Windows Hello",
        "model": "Microsoft Windows Hello (TPM 2.0)",
        "assurance": "L2 - Hardware TPM Protected",
        "form_factor": "platform",
    },
    # Yubico Security Keys
    "ee5537a5-911a-4c91-881e-9883380b997f": {
        "vendor": "Yubico",
        "model": "YubiKey 5 Series (NFC / USB-C)",
        "assurance": "L3 - FIPS 140-2 Level 3 Hardware",
        "form_factor": "roaming",
    },
    "cb69481e-8ff7-4039-93ec-0a2729a1d67b": {
        "vendor": "Yubico",
        "model": "YubiKey 5 FIPS Series",
        "assurance": "L3 - FIPS 140-3 Approved",
        "form_factor": "roaming",
    },
    "fa2b99dc-9e39-4257-8f92-4a30d23c4118": {
        "vendor": "Yubico",
        "model": "YubiKey Bio Series (Biometric Hardware)",
        "assurance": "L3 - Biometric Hardware Sensor",
        "form_factor": "roaming",
    },
    # Google Titan
    "42358055-680c-4861-a08b-6f29da2d80d5": {
        "vendor": "Google",
        "model": "Google Titan Security Key",
        "assurance": "L3 - Common Criteria EAL6+ Chip",
        "form_factor": "roaming",
    },
}


def resolve_aaguid(aaguid: str | None) -> dict[str, str]:
    """Look up authenticator metadata from registered AAGUID database."""
    if not aaguid:
        return {
            "vendor": "Generic Passkey",
            "model": "Passkey / Software Authenticator",
            "assurance": "L1 - Standard Identity",
            "form_factor": "synced",
        }

    clean_guid = aaguid.lower().strip()
    return KNOWN_AAGUIDS.get(
        clean_guid,
        {
            "vendor": "FIDO2 Authenticator",
            "model": f"Hardware Token ({clean_guid[:8]}...)",
            "assurance": "L2 - CTAP2 Security Token",
            "form_factor": "hardware",
        },
    )
