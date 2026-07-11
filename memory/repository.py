from sqlalchemy import select
from sqlalchemy.orm import Session

from memory.models import Finding, Project


def get_or_create_project(session: Session, name: str, path: str) -> Project:
    project = session.scalar(select(Project).where(Project.name == name))
    if project is not None:
        return project
    project = Project(name=name, path=path)
    session.add(project)
    session.commit()
    session.refresh(project)
    return project


def save_findings(session: Session, project: Project, findings: list[dict]) -> list[Finding]:
    rows = []
    for f in findings:
        row = Finding(
            project_id=project.id,
            source_tool=f["source_tool"],
            severity=f.get("severity", "info"),
            title=f["title"],
            description=f.get("description", ""),
            file_path=f.get("file_path"),
            line=f.get("line"),
            sensitive=f.get("sensitive", False),
        )
        session.add(row)
        rows.append(row)
    session.commit()
    for row in rows:
        session.refresh(row)
    return rows


def list_findings_for_project(session: Session, project: Project) -> list[Finding]:
    return list(session.scalars(select(Finding).where(Finding.project_id == project.id)))
