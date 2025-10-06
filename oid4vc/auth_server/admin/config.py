"""Application configuration."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application configuration."""

    model_config = SettingsConfigDict(env_prefix="ADMIN_", extra="ignore")

    APP_ROOT_PATH: str = ""
    APP_TITLE: str = "OAuth 2.0 Authorization Server Admin API"
    APP_VERSION: str = "0.1.0"
    OPENAPI_URL: str = ""

    OAUTH_ISSUER: str = ""
    OAUTH_CLIENT_ID: str = ""
    OAUTH_JWKS_URL: str = ""
    MANAGE_AUTH_TOKEN: str = "manage_auth_token"

    DB_DRIVER_ASYNC: str = "postgresql+asyncpg"
    DB_DRIVER_SYNC: str = "postgresql+psycopg"
    DB_HOST: str = "localhost"
    DB_PORT: int = 5432

    DB_NAME: str = "auth_server_admin"
    DB_SCHEMA: str = "admin"
    DB_USER: str = "postgres"
    DB_PASSWORD: str = "postgres"

    TENANT_DB_NAME: str = "auth_server_tenant"
    TENANT_DB_SCHEMA: str = "auth"

    INTERNAL_AUTH_TOKEN: str = "internal_auth_token"

    KEY_VERIFY_GRACE_TTL: int = 604800  # seconds, JWKS grace after retirement
    KEY_ENC_SECRETS: dict[str, str] = {}
    KEY_ENC_VERSION: int = 1

    # CORS settings
    CORS_ALLOW_ORIGINS: list[str] = ["*"]
    CORS_ALLOW_METHODS: list[str] = ["GET", "POST", "PATCH", "DELETE", "OPTIONS"]
    CORS_ALLOW_HEADERS: list[str] = ["Authorization", "Content-Type"]
    CORS_ALLOW_CREDENTIALS: bool = False

    @property
    def KEY_ENC_SECRET(self) -> str | None:
        """Return the active key string directly, based on KEY_ENC_VERSION."""
        return self.KEY_ENC_SECRETS.get(str(self.KEY_ENC_VERSION))

    @property
    def DB_URL(self) -> str:
        """Async DB connection string."""
        return self._get_db_conn_str(use_async=True)

    @property
    def DB_URL_SYNC(self) -> str:
        """Sync DB connection string."""
        return self._get_db_conn_str(use_async=False)

    def _get_db_conn_str(self, use_async: bool = True) -> str:
        """Return DB connection string by protocol."""
        DB_DRIVER = self.DB_DRIVER_ASYNC if use_async else self.DB_DRIVER_SYNC
        return (
            f"{DB_DRIVER}://"
            f"{self.DB_USER}:{self.DB_PASSWORD}"
            f"@{self.DB_HOST}:{self.DB_PORT}"
            f"/{self.DB_NAME}"
        )


settings = Settings()
