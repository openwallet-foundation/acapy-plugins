"""Data-access layer for the admin database."""

from datetime import datetime

from sqlalchemy import BigInteger, Boolean, ForeignKey, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB, TIMESTAMP
from sqlalchemy.orm import Mapped, mapped_column

from core.models import Base
from admin.config import settings


class Tenant(Base):
    """Tenant model."""

    __tablename__ = "tenant"
    __table_args__ = (
        UniqueConstraint("uid", name="uq_tenant_uid"),
        {"schema": settings.DB_SCHEMA},
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    uid: Mapped[str] = mapped_column(Text, nullable=False)
    name: Mapped[str | None] = mapped_column(Text, nullable=True)

    db_name: Mapped[str | None] = mapped_column(Text, nullable=True)
    db_schema: Mapped[str | None] = mapped_column(Text, nullable=True)
    db_user: Mapped[str | None] = mapped_column(Text, nullable=True)
    db_pwd_enc: Mapped[str | None] = mapped_column(Text, nullable=True)

    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, default=func.now()
    )
    updated_at: Mapped[datetime | None] = mapped_column(
        TIMESTAMP(timezone=True), nullable=True, onupdate=func.now()
    )
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)


class TenantKey(Base):
    """Tenant signing key model."""

    __tablename__ = "tenant_key"
    __table_args__ = (
        UniqueConstraint("tenant_id", "kid", name="uq_key_tenant_kid"),
        {"schema": settings.DB_SCHEMA},
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)

    tenant_id: Mapped[int] = mapped_column(
        ForeignKey(f"{settings.DB_SCHEMA}.tenant.id", ondelete="CASCADE"),
        nullable=False,
    )

    kid: Mapped[str] = mapped_column(Text, nullable=False)
    alg: Mapped[str] = mapped_column(Text, nullable=False)
    public_jwk: Mapped[dict] = mapped_column(JSONB, nullable=False)
    private_pem_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(Text, default="active", nullable=False)
    not_before: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, default=func.now()
    )
    not_after: Mapped[datetime | None] = mapped_column(
        TIMESTAMP(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, default=func.now()
    )
    updated_at: Mapped[datetime | None] = mapped_column(
        TIMESTAMP(timezone=True), nullable=True, onupdate=func.now()
    )
