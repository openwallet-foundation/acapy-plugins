"""Application configuration."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application configuration."""

    model_config = SettingsConfigDict(env_prefix="TENANT_", extra="ignore")

    APP_ROOT_PATH: str = ""
    APP_TITLE: str = "OAuth 2.0 Authorization Server Tenant API"
    APP_VERSION: str = "0.1.0"
    OPENAPI_URL: str = ""

    ISSUER_BASE_URL: str = "http://localhost:9001"

    ACCESS_TOKEN_TTL: int = 900
    REFRESH_TOKEN_TTL: int = 604800
    PRE_AUTH_CODE_TTL: int = 600
    TOKEN_BYTES: int = 48
    INCLUDE_NONCE: bool = False
    NONCE_BYTES: int = 16

    DB_DRIVER_ASYNC: str = "postgresql+asyncpg"
    DB_DRIVER_SYNC: str = "postgresql+psycopg"
    DB_HOST: str = "localhost"
    DB_PORT: int = 5432

    TRUSTED_NETWORKS: list[str] = []

    ADMIN_INTERNAL_BASE_URL: str = "http://localhost:9000"
    ADMIN_INTERNAL_AUTH_TOKEN: str = "admin-internal-auth-token"
    CONTEXT_CACHE_TTL: int = 900
    WELL_KNOWN_CACHE_TTL: int = 300

    KEY_ENC_SECRETS: dict[str, str] = {}
    KEY_ENC_VERSION: int = 1

    # CORS settings
    CORS_ALLOW_ORIGINS: list[str] = ["*"]
    CORS_ALLOW_METHODS: list[str] = ["GET", "POST", "OPTIONS"]
    CORS_ALLOW_HEADERS: list[str] = ["Authorization", "Content-Type"]
    CORS_ALLOW_CREDENTIALS: bool = False


settings = Settings()
