"""Configuration settings for Enterprise WebAuthn Gateway."""


from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Relying Party Settings
    RP_ID: str = "localhost"
    RP_NAME: str = "Enterprise WebAuthn Gateway"
    EXPECTED_ORIGIN: str | list[str] = [
        "http://localhost:8000",
        "https://localhost:8000",
        "http://localhost:8443",
        "https://localhost:8443",
        "http://127.0.0.1:8000",
        "https://127.0.0.1:8000",
        "http://localhost",
        "https://localhost",
    ]

    # Security & Challenges
    CHALLENGE_TIMEOUT_SECONDS: int = 120
    JWT_SECRET_KEY: str = "super-secret-enterprise-fido2-gateway-jwt-key-change-in-production"
    JWT_ALGORITHM: str = "HS256"
    SESSION_EXPIRATION_MINUTES: int = 60
    STEP_UP_MAX_AGE_SECONDS: int = 60  # Require fresh auth within 60s for sensitive routes
    COOKIE_NAME: str = "fido2_session"

    # Infrastructure & Upstream Service
    UPSTREAM_URL: str = "http://localhost:8001"
    DATABASE_URL: str = "sqlite+aiosqlite:///./gateway.db"
    REDIS_URL: str = "redis://localhost:6379/0"

    # Algorithm preferences: ES256 (-7), RS256 (-257), EdDSA (-8)
    SUPPORTED_COSE_ALGORITHMS: list[int] = [-7, -257, -8]

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    @field_validator("EXPECTED_ORIGIN", mode="before")
    @classmethod
    def parse_expected_origin(cls, v):
        if isinstance(v, str):
            if "," in v:
                return [o.strip() for o in v.split(",") if o.strip()]
            return [v.strip()]
        return v


settings = Settings()
