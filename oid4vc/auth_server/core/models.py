"""Shared models."""

from datetime import datetime

from sqlalchemy import (
    Integer,
    MetaData,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, TIMESTAMP
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Base class for declarative models."""

    metadata = MetaData()


class Client(Base):
    """OAuth2 client registration for issuer->tenant auth."""

    __tablename__ = "client"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    client_id: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    client_auth_method: Mapped[str] = mapped_column(Text, nullable=False)
    client_auth_signing_alg: Mapped[str | None] = mapped_column(Text, nullable=True)
    client_secret: Mapped[str | None] = mapped_column(Text, nullable=True)
    jwks: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    jwks_uri: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, default=func.now()
    )
    updated_at: Mapped[datetime | None] = mapped_column(
        TIMESTAMP(timezone=True), nullable=True, onupdate=func.now()
    )
