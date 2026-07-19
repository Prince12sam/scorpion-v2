import uuid
from datetime import datetime, timezone

from pgvector.sqlalchemy import Vector
from sqlalchemy import JSON, DateTime, ForeignKey, String, Text, Boolean
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

# Must match the embedding model configured in api/llm_router.py.
EMBEDDING_DIM = 1536


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _uuid() -> uuid.UUID:
    return uuid.uuid4()


class Base(DeclarativeBase):
    pass


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(255), unique=True)
    path: Mapped[str] = mapped_column(String(1024))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    findings: Mapped[list["Finding"]] = relationship(back_populates="project")
    notes: Mapped[list["Note"]] = relationship(back_populates="project")


class Target(Base):
    """A network host, domain, or repo scope record.

    See docs/SECURITY_AND_AUTHORIZATION.md for the verification model this
    backs. Not required for local-only `analyze`/`fix` — only Phase 2's
    Tool Orchestrator (network-facing tools) enforces this table.
    """

    __tablename__ = "targets"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    identifier: Mapped[str] = mapped_column(String(512), unique=True)
    status: Mapped[str] = mapped_column(String(32), default="unverified")  # unverified|verified|revoked
    verification_method: Mapped[str | None] = mapped_column(String(512), nullable=True)
    authorized_actions: Mapped[list] = mapped_column(JSON, default=list)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    # Full SOW text, kept only when the "exploitation" tier was granted via
    # api/sow.py — the accountability record behind that specific decision,
    # same principle as self-attestation's logged statement.
    sow_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Deliverable/report content requirements api/sow.py's LLM analysis
    # extracted from the same SOW (e.g. "executive summary", "CVSS score
    # per finding") — empty list if the SOW didn't specify a report format.
    # Only ever set alongside sow_text, by the same verify_sow() call.
    report_requirements: Mapped[list] = mapped_column(JSON, default=list)


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    project_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("projects.id"), nullable=True)
    target_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("targets.id"), nullable=True)
    source_tool: Mapped[str] = mapped_column(String(128))
    severity: Mapped[str] = mapped_column(String(32), default="info")
    title: Mapped[str] = mapped_column(String(512))
    description: Mapped[str] = mapped_column(Text, default="")
    file_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    line: Mapped[int | None] = mapped_column(nullable=True)
    sensitive: Mapped[bool] = mapped_column(Boolean, default=False)
    embedding: Mapped[list[float] | None] = mapped_column(Vector(EMBEDDING_DIM), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    project: Mapped["Project | None"] = relationship(back_populates="findings")


class Note(Base):
    __tablename__ = "notes"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    project_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("projects.id"), nullable=True)
    content: Mapped[str] = mapped_column(Text)
    embedding: Mapped[list[float] | None] = mapped_column(Vector(EMBEDDING_DIM), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    project: Mapped["Project | None"] = relationship(back_populates="notes")


class CredentialRef(Base):
    """Reference only — never the secret value. See
    docs/SECURITY_AND_AUTHORIZATION.md 'Secrets and data egress'."""

    __tablename__ = "credential_refs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    type: Mapped[str] = mapped_column(String(64))
    location: Mapped[str] = mapped_column(String(1024))
    value_hash: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
