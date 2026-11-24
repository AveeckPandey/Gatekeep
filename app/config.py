import os
import secrets
from typing import Optional

from cryptography.fernet import Fernet
from pydantic import AliasChoices, Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

KNOWN_INSECURE_JWT_KEYS = {
    "gatekeep-super-secret-jwt-signing-key-for-phase-1-testing",
    "gatekeep-production-jwt-secret-key-32chars",
    "ci-cd-testing-secret-key-32-chars-long",
}

KNOWN_INSECURE_FERNET_KEYS = {
    "8t_tH5x_ci-cd-test-fernet-key-32bytes=",
    "Z2F0ZWtlZXAtdGVzdC1mZXJuZXQta2V5LTMyYnl0ZXM=",
}


class Settings(BaseSettings):
    APP_NAME: str = "GateKeep"
    ENV: str = "development"
    DEBUG: bool = False
    AUTH_BACKEND: str = "local"  # local for development; cognito for deployed control plane
    COGNITO_REGION: Optional[str] = None
    COGNITO_USER_POOL_ID: Optional[str] = None
    COGNITO_APP_CLIENT_ID: Optional[str] = None
    ENABLE_DEMO_ENDPOINT: bool = False
    CORS_ORIGINS: str = "http://localhost:3000,http://127.0.0.1:3000"

    # Control Plane Auth (JWT)
    JWT_SECRET_KEY: str = Field(default_factory=lambda: secrets.token_urlsafe(48))
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 60 * 24  # 24 hours

    # BYOK Encryption at rest (Fernet key - 32 url-safe base64-encoded bytes)
    # Default key is provided for local dev/testing; must be set to a secure unique key in production
    ENCRYPTION_KEY: str = Field(
        default_factory=lambda: Fernet.generate_key().decode("utf-8"),
        validation_alias=AliasChoices("GATEKEEP_ENCRYPTION_KEY", "ENCRYPTION_KEY"),
    )

    # Upstream LLM default (NVIDIA Nemotron / OpenAI compatible)
    DEFAULT_UPSTREAM_BASE_URL: str = "https://integrate.api.nvidia.com/v1"
    GOOGLE_OPENAI_BASE_URL: str = "https://generativelanguage.googleapis.com/v1beta/openai"
    UPSTREAM_PROVIDERS: str = "{}"  # JSON registry of server-managed providers

    # Shannon entropy threshold for secret detection (catches random hex >= 3.7 and base64 tokens >= 4.0)
    ENTROPY_THRESHOLD: float = 3.7
    MIN_ENTROPY_STRING_LEN: int = 16

    # Database / Storage Backend ("in_memory" or "dynamodb")
    REPOSITORY_BACKEND: str = os.getenv("REPOSITORY_BACKEND", "dynamodb")
    DYNAMODB_TABLE_NAME: str = os.getenv("DYNAMODB_TABLE_NAME", "gatekeep-main")
    AWS_REGION: str = os.getenv("AWS_REGION", "us-east-1")
    DYNAMODB_ENDPOINT_URL: Optional[str] = os.getenv("DYNAMODB_ENDPOINT_URL", None)
    AWS_ACCESS_KEY_ID: Optional[str] = os.getenv("AWS_ACCESS_KEY_ID", None)
    AWS_SECRET_ACCESS_KEY: Optional[str] = os.getenv("AWS_SECRET_ACCESS_KEY", None)

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    @model_validator(mode="after")
    def validate_production_secrets(self) -> "Settings":
        """In production, prevent the use of known insecure secrets or missing encryption keys."""
        if self.ENV == "production":
            if "JWT_SECRET_KEY" not in self.model_fields_set or "ENCRYPTION_KEY" not in self.model_fields_set:
                # The encryption key also accepts the GATEKEEP_ENCRYPTION_KEY alias.
                raise RuntimeError("Production JWT and encryption keys must be configured explicitly")
            if (
                not self.JWT_SECRET_KEY
                or self.JWT_SECRET_KEY in KNOWN_INSECURE_JWT_KEYS
                or len(self.JWT_SECRET_KEY) < 32
            ):
                raise RuntimeError(
                    "Insecure JWT_SECRET_KEY configured for production: "
                    "must be at least 32 characters and not use known default values."
                )

            if (
                not self.ENCRYPTION_KEY
                or self.ENCRYPTION_KEY in KNOWN_INSECURE_FERNET_KEYS
            ):
                raise RuntimeError(
                    "Insecure or missing GATEKEEP_ENCRYPTION_KEY in production: "
                    "must not use known default test values."
                )

            try:
                Fernet(self.ENCRYPTION_KEY.encode("utf-8"))
            except Exception as e:
                raise RuntimeError(f"Invalid GATEKEEP_ENCRYPTION_KEY in production: {e}")

            if self.AUTH_BACKEND != "cognito":
                raise RuntimeError("Production requires AUTH_BACKEND=cognito")
            if not all((self.COGNITO_REGION, self.COGNITO_USER_POOL_ID, self.COGNITO_APP_CLIENT_ID)):
                raise RuntimeError("Cognito region, user pool ID and app client ID are required")

        return self


settings = Settings()
