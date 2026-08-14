from alembic import op

revision = "0002_tx_code_and_jti_seen"
down_revision = "0001_init_tenant"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        ALTER TABLE pre_auth_code
        ADD COLUMN IF NOT EXISTS user_pin_attempts INTEGER NOT NULL DEFAULT 0;

        CREATE TABLE IF NOT EXISTS jti_seen (
            jti TEXT PRIMARY KEY,
            expires_at TIMESTAMPTZ NOT NULL,
            metadata JSONB
        );
        CREATE INDEX IF NOT EXISTS ix_jti_seen_expires_at
            ON jti_seen (expires_at);

        DROP TABLE IF EXISTS dpop_jti;
    """)


def downgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS dpop_jti (
            id SERIAL PRIMARY KEY,
            subject_id INTEGER NOT NULL REFERENCES subject(id)
                ON UPDATE CASCADE ON DELETE CASCADE,
            jti TEXT NOT NULL UNIQUE,
            htm TEXT,
            htu TEXT,
            cnf_jkt TEXT,
            issued_at TIMESTAMPTZ NOT NULL,
            expires_at TIMESTAMPTZ NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_dpop_jti_expires_at
            ON dpop_jti (expires_at);

        DROP INDEX IF EXISTS ix_jti_seen_expires_at;
        DROP TABLE IF EXISTS jti_seen;

        ALTER TABLE pre_auth_code
        DROP COLUMN IF EXISTS user_pin_attempts;
    """)
