import base64
import os
from pydantic_settings import BaseSettings, SettingsConfigDict
from cryptography.fernet import Fernet


class Settings(BaseSettings):
    APP_NAME: str = "GateKeep"
    ENV: str = "development"
    DEBUG: bool = False

    # Control Plane Auth (JWT)
    JWT_SECRET_KEY: str = "gatekeep-super-secret-jwt-signing-key-for-phase-1-testing"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 60 * 24  # 24 hours

    # BYOK Encryption at rest (Fernet key - 32 url-safe base64-encoded bytes)
    # Default key is provided for testing, must be set in production
    ENCRYPTION_KEY: str = os.getenv(
        "GATEKEEP_ENCRYPTION_KEY",
        Fernet.generate_key().decode()
    )

    # Upstream LLM default (NVIDIA Nemotron / OpenAI compatible)
    DEFAULT_UPSTREAM_BASE_URL: str = "https://integrate.api.nvidia.com/v1"

    # Shannon entropy threshold for secret detection (catches random hex >= 3.7 and base64 tokens >= 4.0)
    ENTROPY_THRESHOLD: float = 3.7
    MIN_ENTROPY_STRING_LEN: int = 16

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")


settings = Settings()
