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
