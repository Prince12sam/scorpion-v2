from pydantic import BaseModel


class AnalyzeRequest(BaseModel):
    path: str
    project_name: str | None = None


class Finding(BaseModel):
    source_tool: str
    severity: str
    title: str
    description: str
    file_path: str | None = None
    line: int | None = None


class AnalyzeResponse(BaseModel):
    findings: list[Finding]
    summary: str
    error: str | None = None


class FixProposeRequest(BaseModel):
    path: str


class FixProposeResponse(BaseModel):
    findings: list[Finding]
    diff: str
    error: str | None = None


class FixApplyRequest(BaseModel):
    path: str
    diff: str
    commit: bool = False


class FixApplyResponse(BaseModel):
    applied: bool
    committed: bool
    test_output: str
    error: str | None = None


class ScanRequest(BaseModel):
    target: str


class ScanResponse(BaseModel):
    findings: list[Finding]
    warnings: list[str]
    summary: str
    # Deliverable/report content requirements extracted from the target's
    # SOW (api/sow.py), if it was authorized via one — empty otherwise.
    report_requirements: list[str] = []


class ScanApiRequest(BaseModel):
    target: str
    spec: str
    target_override: str | None = None
    auth_header: str | None = None


class ScanApiResponse(BaseModel):
    findings: list[Finding]
    warnings: list[str]
    summary: str
    report_requirements: list[str] = []


class VerifyTargetRequest(BaseModel):
    target: str
    token: str


class VerifyTargetResponse(BaseModel):
    status: str
    verification_method: str | None = None
    error: str | None = None


class TargetStatusRequest(BaseModel):
    target: str


class TargetStatusResponse(BaseModel):
    status: str
    verification_method: str | None = None
    expires_at: str | None = None


class SelfAttestRequest(BaseModel):
    target: str
    statement: str


class ScanProgressResponse(BaseModel):
    running: bool
    stage: str | None = None
    stage_index: int | None = None
    stage_total: int | None = None
    elapsed_seconds: float | None = None


class SowAuthorizeRequest(BaseModel):
    target: str
    sow_text: str


class SowAuthorizeResponse(BaseModel):
    status: str
    verification_method: str | None = None
    exploitation_authorized: bool = False
    error: str | None = None
