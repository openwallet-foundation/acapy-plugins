"""Admin settings."""

from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import URL


class Settings(BaseSettings):
    """Admin env vars (ADMIN_ prefix)."""

    model_config = SettingsConfigDict(env_prefix="ADMIN_", extra="ignore")

    # App metadata
    APP_ROOT_PATH: str = ""
    APP_TITLE: str = "OAuth 2.0 Authorization Server Admin API"
    APP_VERSION: str = "0.1.0"
    OPENAPI_URL: str = ""

    # Bearer tokens
    MANAGE_AUTH_TOKEN: str = ""
    INTERNAL_AUTH_TOKEN: str = ""

    # Database
    DB_DRIVER_ASYNC: str = "postgresql+asyncpg"
    DB_DRIVER_SYNC: str = "postgresql+psycopg"
    DB_HOST: str = "localhost"
    DB_PORT: int = 5432
    DB_NAME: str = "auth_server_admin"
    DB_SCHEMA: str = "admin"
    DB_USER: str = "postgres"
    DB_PASSWORD: str = "postgres"

    # Tenant database
    TENANT_DB_NAME: str = "auth_server_tenant"
    TENANT_DB_SCHEMA: str = "auth"

    # Client settings
    MIN_CLIENT_SECRET_LENGTH: int = 32

    # Key encryption
    KEY_VERIFY_GRACE_TTL: int = 604800  # seconds, JWKS grace after retirement
    KEY_ENC_SECRETS: dict[str, str] = {}
    KEY_ENC_VERSION: int = 1

    # CORS
    CORS_ALLOW_ORIGINS: list[str] = []
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
        driver = self.DB_DRIVER_ASYNC if use_async else self.DB_DRIVER_SYNC
        return URL.create(
            drivername=driver,
            username=self.DB_USER,
            password=self.DB_PASSWORD,
            host=self.DB_HOST,
            port=self.DB_PORT,
            database=self.DB_NAME,
        ).render_as_string(hide_password=False)


settings = Settings()
