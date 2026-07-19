from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from api import scan_status
from api.agents.pentest_agent import scan as run_scan
from api.agents.pentest_agent import summarize_findings
from api.schemas import (
    ScanApiRequest,
    ScanApiResponse,
    ScanProgressResponse,
    ScanRequest,
    ScanResponse,
    SelfAttestRequest,
    SowAuthorizeRequest,
    SowAuthorizeResponse,
    TargetStatusRequest,
    TargetStatusResponse,
    VerifyTargetRequest,
    VerifyTargetResponse,
)
from api.scope import (
    ACTIVE_SCAN,
    EXPLOITATION,
    ScopeDenied,
    effective_status,
    get_or_create_target,
    get_target_status,
    require_authorized,
    verify_file_token,
    verify_self_attestation,
    verify_sow,
)
from api.sow import SowParseError, parse_sow
from api.tool_router import ToolError, run_zap_api_scan
from memory.db import get_session
from memory.repository import save_findings_for_target

router = APIRouter(prefix="/v1", tags=["scan"])


@router.post("/targets/verify", response_model=VerifyTargetResponse)
def verify_target(req: VerifyTargetRequest, session: Session = Depends(get_session)) -> VerifyTargetResponse:
    try:
        target = verify_file_token(session, req.target, req.token)
    except ScopeDenied as exc:
        return VerifyTargetResponse(status="unverified", error=str(exc))
    return VerifyTargetResponse(status=target.status, verification_method=target.verification_method)


@router.post("/targets/status", response_model=TargetStatusResponse)
def target_status(req: TargetStatusRequest, session: Session = Depends(get_session)) -> TargetStatusResponse:
    target = get_target_status(session, req.target)
    return TargetStatusResponse(
        # effective_status(), not target.status directly — the DB column
        # never flips back on its own when a TTL passes, so reading it raw
        # here would tell the CLI a stale "verified" target is still good,
        # skip re-attesting, and then have every stage get denied anyway.
        status=effective_status(target),
        verification_method=target.verification_method,
        expires_at=target.expires_at.isoformat() if target.expires_at else None,
    )


@router.post("/targets/self-attest", response_model=VerifyTargetResponse)
def self_attest(req: SelfAttestRequest, session: Session = Depends(get_session)) -> VerifyTargetResponse:
    target = verify_self_attestation(session, req.target, req.statement)
    return VerifyTargetResponse(status=target.status, verification_method=target.verification_method)


@router.post("/targets/authorize-sow", response_model=SowAuthorizeResponse)
def authorize_sow(req: SowAuthorizeRequest, session: Session = Depends(get_session)) -> SowAuthorizeResponse:
    try:
        parsed = parse_sow(req.sow_text)
    except SowParseError as exc:
        return SowAuthorizeResponse(status="unverified", error=str(exc))

    if req.target not in parsed.get("targets", []):
        return SowAuthorizeResponse(
            status="unverified",
            error=(
                f"'{req.target}' is not among the targets explicitly named in the SOW "
                f"({parsed.get('targets', [])}) — refusing to authorize a target the "
                "document doesn't actually cover."
            ),
        )

    target = verify_sow(session, req.target, req.sow_text, parsed)
    return SowAuthorizeResponse(
        status=target.status,
        verification_method=target.verification_method,
        exploitation_authorized=EXPLOITATION in (target.authorized_actions or []),
    )


@router.get("/scan/progress", response_model=ScanProgressResponse)
def scan_progress(target: str) -> ScanProgressResponse:
    info = scan_status.get(target)
    if info is None:
        return ScanProgressResponse(running=False)
    return ScanProgressResponse(
        running=True,
        stage=info["stage"],
        stage_index=info["index"],
        stage_total=info["total"],
        elapsed_seconds=round(info["elapsed_seconds"], 1),
    )


@router.post("/scan", response_model=ScanResponse)
def scan_target(req: ScanRequest, session: Session = Depends(get_session)) -> ScanResponse:
    result = run_scan(session, req.target)

    report_requirements: list[str] = []
    try:
        target_row = get_or_create_target(session, req.target)
        report_requirements = target_row.report_requirements or []
        save_findings_for_target(session, target_row, result["findings"])
    except Exception as exc:  # noqa: BLE001 - Memory being down shouldn't hide scan results
        session.rollback()
        result["warnings"].append(f"findings were not persisted to Memory: {exc}")

    return ScanResponse(
        findings=result["findings"],
        warnings=result["warnings"],
        summary=result["summary"],
        report_requirements=report_requirements,
    )


@router.post("/scan-api", response_model=ScanApiResponse)
def scan_api_target(req: ScanApiRequest, session: Session = Depends(get_session)) -> ScanApiResponse:
    warnings: list[str] = []
    findings: list[dict] = []

    try:
        require_authorized(session, req.target, ACTIVE_SCAN)
    except ScopeDenied as exc:
        warnings.append(f"zap-api-scan: skipped — {exc}")
        return ScanApiResponse(findings=[], warnings=warnings, summary="No findings.")

    scan_status.set_stage(req.target, "zap-api-scan", 1, 2)
    try:
        findings = run_zap_api_scan(req.spec, target_override=req.target_override, auth_header=req.auth_header)
    except ToolError as exc:
        warnings.append(f"zap-api-scan: {exc}")
    finally:
        scan_status.clear(req.target)

    report_requirements: list[str] = []
    try:
        target_row = get_or_create_target(session, req.target)
        report_requirements = target_row.report_requirements or []
        save_findings_for_target(session, target_row, findings)
    except Exception as exc:  # noqa: BLE001 - Memory being down shouldn't hide scan results
        session.rollback()
        warnings.append(f"findings were not persisted to Memory: {exc}")

    scan_status.set_stage(req.target, "summarize (LLM)", 2, 2)
    try:
        summary = summarize_findings(findings, warnings)
    finally:
        scan_status.clear(req.target)
    return ScanApiResponse(
        findings=findings, warnings=warnings, summary=summary, report_requirements=report_requirements
    )
