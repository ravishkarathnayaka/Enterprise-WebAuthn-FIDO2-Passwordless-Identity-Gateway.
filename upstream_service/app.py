"""Upstream Protected Backend Service.

This service lives behind the WebAuthn Identity Gateway and expects
identity headers injected by the reverse proxy.
"""


from fastapi import FastAPI, Header, HTTPException, status
from pydantic import BaseModel

app = FastAPI(
    title="Protected Upstream Microservice",
    description="Internal backend service accessible solely via WebAuthn Gateway reverse proxy",
    version="1.0.0",
)


class TransferPayload(BaseModel):
    recipient: str
    amount: float
    description: str | None = None


@app.get("/")
async def root(
    x_authenticated_user: str | None = Header(None),
    x_user_id: str | None = Header(None),
    x_passkey_credential_id: str | None = Header(None),
    x_user_verified: str | None = Header(None),
):
    """Protected root echoing forwarded gateway identity."""
    if not x_authenticated_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing gateway identity header. Access must occur via WebAuthn Reverse Proxy.",
        )
    return {
        "service": "Protected Upstream Microservice",
        "status": "online",
        "authenticated_caller": {
            "username": x_authenticated_user,
            "user_id": x_user_id,
            "passkey_id": x_passkey_credential_id,
            "user_verified": x_user_verified == "true",
        },
    }


@app.get("/api/confidential-records")
async def get_confidential_records(
    x_authenticated_user: str | None = Header(None),
    x_user_id: str | None = Header(None),
    x_user_verified: str | None = Header(None),
):
    """Confidential enterprise data available only to passkey-authenticated identities."""
    if not x_authenticated_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Direct unauthenticated access forbidden. Route requests via Identity Gateway.",
        )

    return {
        "classification": "TOP SECRET // RESTRICTED",
        "authorized_principal": x_authenticated_user,
        "identity_assurance_level": "AAL3 (Hardware FIDO2 Token)",
        "user_verification_enforced": x_user_verified == "true",
        "records": [
            {
                "id": "SEC-2026-001",
                "title": "SOC 2 Type II Cryptographic Attestation Report",
                "status": "Compliant",
                "auditor": "Big4 Enterprise Assurance LLC",
            },
            {
                "id": "SEC-2026-002",
                "title": "Quantum-Resistant HSM Hardware Key Inventory",
                "status": "Rotated",
                "hsm_cluster": "us-east-cluster-04",
            },
            {
                "id": "FIN-2026-889",
                "title": "Corporate Treasury Clearing Ledger",
                "balance": "$48,250,000.00 USD",
                "multisig_state": "Armed",
            },
        ],
    }


@app.post("/api/admin/transfer")
async def execute_transfer(
    payload: TransferPayload,
    x_authenticated_user: str | None = Header(None),
    x_auth_time: str | None = Header(None),
):
    """Internal transfer fulfillment endpoint."""
    if not x_authenticated_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Gateway authentication required.",
        )

    return {
        "status": "processed",
        "transfer_id": "TX-99018472",
        "recipient": payload.recipient,
        "amount": payload.amount,
        "authorized_by": x_authenticated_user,
        "auth_timestamp": x_auth_time,
    }
