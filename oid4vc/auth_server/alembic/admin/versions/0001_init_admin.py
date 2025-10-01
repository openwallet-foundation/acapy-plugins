from pathlib import Path
from alembic import op

revision = "0001_init_admin"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    sql_path = Path(__file__).resolve().parents[2] / "sql" / "admin.sql"
    op.execute(sql_path.read_text())


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS admin.tenant;")
