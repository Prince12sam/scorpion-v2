from collections.abc import Generator

from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from api.config import settings
from memory.models import Base

engine = create_engine(settings.database_url, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


def init_db() -> None:
    with engine.begin() as conn:
        conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
    Base.metadata.create_all(bind=engine)
    # create_all() only creates tables that don't exist yet — it never
    # alters an existing one. Real deployments keep a persisted Postgres
    # volume across sessions (see docker/.env.example's es_pg_data), so a
    # column added to a model here (e.g. Target.sow_text) needs an
    # explicit, additive migration or every query against the row hits
    # UndefinedColumn on any install that predates the change. No
    # migration framework for a project this size yet — just add an
    # idempotent ALTER TABLE here when a column is added to an existing
    # model.
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE targets ADD COLUMN IF NOT EXISTS sow_text TEXT"))
        conn.execute(
            text("ALTER TABLE targets ADD COLUMN IF NOT EXISTS report_requirements JSON DEFAULT '[]'::json")
        )


def get_session() -> Generator[Session, None, None]:
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
