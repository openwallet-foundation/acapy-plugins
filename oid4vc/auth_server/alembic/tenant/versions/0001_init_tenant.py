from pathlib import Path
from alembic import op

revision = "0001_init_tenant"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    sql_path = Path(__file__).resolve().parents[2] / "sql" / "tenant.sql"
    op.execute(sql_path.read_text())


def downgrade() -> None:
    op.execute("""
      DROP TABLE IF EXISTS auth.nonce;
      DROP TABLE IF EXISTS auth.dpop_jti;
      DROP TABLE IF EXISTS auth.refresh_token;
      DROP TABLE IF EXISTS auth.access_token;
      DROP TABLE IF EXISTS auth.pre_auth_code;
      DROP TABLE IF EXISTS auth.subject;
      DROP TABLE IF EXISTS auth.client;
    """)
