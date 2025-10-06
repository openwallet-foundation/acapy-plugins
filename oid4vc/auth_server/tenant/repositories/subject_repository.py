"""Subject repository."""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from tenant.models import Subject


class SubjectRepository:
    """Repository for subject table."""

    def __init__(self, db: AsyncSession):
        """Constructor."""
        self.db = db

    async def get_id_by_uid(self, uid: str) -> int | None:
        """Return subject.id given subject.uid."""
        stmt = select(Subject.id).where(Subject.uid == uid)
        res = await self.db.execute(stmt)
        return res.scalar_one_or_none()

    async def create(self, uid: str, metadata: dict | None = None) -> Subject:
        """Create a new subject."""
        subject = Subject(uid=uid, subject_metadata=metadata or {})
        self.db.add(subject)
        await self.db.flush()
        return subject
