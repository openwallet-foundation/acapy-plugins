"""Tenant settings."""

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Tenant env vars (TENANT_ prefix)."""

    model_config = SettingsConfigDict(env_prefix="TENANT_", extra="ignore")

    # App metadata
    APP_ROOT_PATH: str = ""
    APP_TITLE: str = "OAuth 2.0 Authorization Server Tenant API"
    APP_VERSION: str = "0.1.0"
    OPENAPI_URL: str = ""
    ISSUER_BASE_URL: str = "http://localhost:9001"

    # Token settings
    ACCESS_TOKEN_TTL: int = 900
    REFRESH_TOKEN_TTL: int = 604800
    PRE_AUTH_CODE_TTL: int = 600
    MAX_TX_CODE_ATTEMPTS: int = 3
    TOKEN_BYTES: int = 48
    INCLUDE_NONCE: bool = False
    NONCE_BYTES: int = 16

    # Attestation
    ATTESTATION_ENABLED: bool = True
    ATTESTATION_REQUIRED: bool = False
    ATTESTATION_CLOCK_SKEW_SECONDS: int = 60

    # Database
    DB_DRIVER_ASYNC: str = "postgresql+asyncpg"
    DB_DRIVER_SYNC: str = "postgresql+psycopg"
    DB_HOST: str = "localhost"
    DB_PORT: int = 5432
    # Sized per replica: total connections = replicas x tenant DBs x (size + overflow)
    DB_POOL_SIZE: int = 5
    DB_MAX_OVERFLOW: int = 10
    DB_POOL_RECYCLE: int = 1800

    # Networking
    TRUSTED_NETWORKS: list[str] = []
    INTERNAL_BASE_URL: str = "http://localhost:9000"
    INTERNAL_AUTH_TOKEN: str = ""

    # Caching
    CONTEXT_CACHE_TTL: int = 900
    WELL_KNOWN_CACHE_TTL: int = 300

    # Key encryption
    KEY_ENC_SECRETS: dict[str, str] = {}
    KEY_ENC_VERSION: int = 1

    # CORS
    CORS_ALLOW_ORIGINS: list[str] = []
    CORS_ALLOW_METHODS: list[str] = ["GET", "POST", "OPTIONS"]
    CORS_ALLOW_HEADERS: list[str] = ["Authorization", "Content-Type"]
    CORS_ALLOW_CREDENTIALS: bool = False

    # Proxy
    PROXY_TRUSTED_HOSTS: list[str] | str = "127.0.0.1"

    @model_validator(mode="after")
    def validate_security_features(self):
        """Reject required security features that are disabled."""
        if self.ATTESTATION_REQUIRED and not self.ATTESTATION_ENABLED:
            raise ValueError("ATTESTATION_REQUIRED requires ATTESTATION_ENABLED")
        return self


settings = Settings()
