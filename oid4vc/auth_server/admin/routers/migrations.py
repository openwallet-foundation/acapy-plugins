"""Router for tenant migrations."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from admin.deps import get_db_session
from admin.security.bearer import require_admin_auth
from admin.repositories.tenant_repository import TenantRepository
from admin.schemas.migration import MigrationAction, MigrationRequest
from admin.services.alembic_service import run_tenant_migration
from admin.utils.db_utils import resolve_tenant_urls
from core.utils.logging import get_logger

logger = get_logger(__name__)

router = APIRouter(dependencies=[Depends(require_admin_auth)])


@router.post("/tenants/{uid}/migrations")
async def migrate_tenant(
    uid: str, body: MigrationRequest, db: AsyncSession = Depends(get_db_session)
):
    """Run migrations for a specific tenant."""

    repo = TenantRepository(db)
    tenant = await repo.get_by_uid(uid)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found or inactive")

    _, sync_url, schema = resolve_tenant_urls(tenant)

    try:
        if body.action == MigrationAction.upgrade:
            rev = body.rev or "head"
            run_tenant_migration(
                sync_url=sync_url, schema=schema, action="upgrade", rev=rev
            )
        else:
            if not body.confirm:
                raise HTTPException(
                    status_code=400,
                    detail="downgrade requires confirm=true",
                )
            rev = body.rev or "-1"
            run_tenant_migration(
                sync_url=sync_url, schema=schema, action="downgrade", rev=rev
            )
    except Exception as ex:
        logger.exception("Alembic migration failed for tenant %s", uid)
        raise HTTPException(status_code=500, detail="migration_failed") from ex

    return {"status": "ok", "action": body.action, "rev": rev, "tenant": uid}
