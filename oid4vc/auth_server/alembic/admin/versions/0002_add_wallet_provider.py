from alembic import op

revision = "0002_add_wallet_provider"
down_revision = "0001_init_admin"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS wallet_provider (
            id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            iss TEXT NOT NULL,
            jwks JSONB,
            jwks_uri TEXT,
            name TEXT,
            active BOOLEAN NOT NULL DEFAULT TRUE,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ,
            UNIQUE (iss)
        );

        CREATE INDEX IF NOT EXISTS idx_wallet_provider_iss
            ON wallet_provider (iss);

        CREATE INDEX IF NOT EXISTS idx_wallet_provider_active
            ON wallet_provider (active);
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS wallet_provider;")
