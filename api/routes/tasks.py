from pathlib import Path

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from api.agents.coding_agent import analyze, apply_fix, propose_fix
from api.schemas import (
    AnalyzeRequest,
    AnalyzeResponse,
    FixApplyRequest,
    FixApplyResponse,
    FixProposeRequest,
    FixProposeResponse,
)
from memory.db import get_session
from memory.repository import get_or_create_project, save_findings

router = APIRouter(prefix="/v1", tags=["tasks"])


@router.post("/analyze", response_model=AnalyzeResponse)
def analyze_path(req: AnalyzeRequest, session: Session = Depends(get_session)) -> AnalyzeResponse:
    result = analyze(req.path)
    memory_error = None

    if not result.get("error"):
        try:
            project_name = req.project_name or Path(req.path).resolve().name
            project = get_or_create_project(session, project_name, str(Path(req.path).resolve()))
            save_findings(session, project, result["findings"])
        except Exception as exc:  # noqa: BLE001 - Memory being down shouldn't hide scan results
            session.rollback()
            memory_error = f"findings were not persisted to Memory: {exc}"

    return AnalyzeResponse(
        findings=result["findings"],
        summary=result["summary"],
        error=result.get("error") or memory_error,
    )


@router.post("/fix/propose", response_model=FixProposeResponse)
def fix_propose(req: FixProposeRequest) -> FixProposeResponse:
    result = propose_fix(req.path)
    return FixProposeResponse(
        findings=result["findings"],
        diff=result["diff"],
        error=result.get("error"),
    )


@router.post("/fix/apply", response_model=FixApplyResponse)
def fix_apply(req: FixApplyRequest) -> FixApplyResponse:
    applied, committed, test_output, error = apply_fix(req.path, req.diff, req.commit)
    return FixApplyResponse(applied=applied, committed=committed, test_output=test_output, error=error)
