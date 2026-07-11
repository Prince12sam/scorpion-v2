from pathlib import Path
from typing import TypedDict

from langgraph.graph import END, StateGraph

from api.config import settings
from api.llm_router import LLMUnavailable, complete
from api.tool_router import ToolError, git_apply_patch, git_commit, run_semgrep, run_tests


class AnalyzeState(TypedDict):
    path: str
    findings: list[dict]
    summary: str
    error: str | None


def _scan_node(state: AnalyzeState) -> AnalyzeState:
    try:
        findings = run_semgrep(Path(state["path"]))
    except ToolError as exc:
        return {**state, "findings": [], "summary": "", "error": str(exc)}
    return {**state, "findings": findings, "error": None}


def _summarize_node(state: AnalyzeState) -> AnalyzeState:
    if state.get("error"):
        return state
    findings = state["findings"]
    if not findings:
        return {**state, "summary": "No findings."}

    listing = "\n".join(
        f"- [{f['severity']}] {f['title']} ({f['file_path']}:{f['line']}) — {f['description']}"
        for f in findings
    )
    prompt = (
        "You are a security code reviewer. Summarize these static-analysis "
        "findings for a developer in a few sentences, grouping by severity, "
        "no fluff:\n\n" + listing
    )
    try:
        summary = complete([{"role": "user", "content": prompt}], purpose="coding")
    except LLMUnavailable as exc:
        summary = f"(LLM summary unavailable: {exc})\n{len(findings)} finding(s) — see raw list."
    return {**state, "summary": summary}


def build_analyze_graph():
    graph = StateGraph(AnalyzeState)
    graph.add_node("scan", _scan_node)
    graph.add_node("summarize", _summarize_node)
    graph.set_entry_point("scan")
    graph.add_edge("scan", "summarize")
    graph.add_edge("summarize", END)
    return graph.compile()


_analyze_graph = build_analyze_graph()


def analyze(path: str) -> AnalyzeState:
    return _analyze_graph.invoke({"path": path, "findings": [], "summary": "", "error": None})


class FixState(TypedDict):
    path: str
    findings: list[dict]
    diff: str
    applied: bool
    committed: bool
    test_output: str
    error: str | None


def _fix_scan_node(state: FixState) -> FixState:
    try:
        findings = run_semgrep(Path(state["path"]))
    except ToolError as exc:
        return {**state, "findings": [], "error": str(exc)}
    return {**state, "findings": findings, "error": None}


MAX_SOURCE_CHARS_PER_FILE = 6000


def _read_source_context(repo_path: Path, findings: list[dict]) -> str:
    """Findings alone (rule id/line/message) aren't enough for a model to
    produce an accurate patch — it needs the real file content, or it
    hallucinates code that was never there. Reads each unique file a
    finding points at, relative to the repo root semgrep scanned."""
    seen: list[str] = []
    for f in findings:
        fp = f.get("file_path")
        if fp and fp not in seen:
            seen.append(fp)

    blocks = []
    for fp in seen:
        # semgrep reports paths as seen inside its container mount (/src/...);
        # strip that prefix to resolve against the real repo on disk.
        relative = fp.split("/src/", 1)[-1] if "/src/" in fp else fp.lstrip("/")
        full_path = repo_path / relative
        try:
            content = full_path.read_text(errors="replace")[:MAX_SOURCE_CHARS_PER_FILE]
        except OSError:
            continue
        blocks.append(f"--- {relative} ---\n{content}")
    return "\n\n".join(blocks)


def _strip_markdown_fences(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        lines = lines[1:]  # drop opening ``` or ```diff
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines)
    return text.strip()


def _fix_patch_node(state: FixState) -> FixState:
    if state.get("error") or not state["findings"]:
        return {**state, "diff": ""}

    findings = state["findings"][: settings.fix_max_findings_per_patch]
    listing = "\n".join(
        f"- [{f['severity']}] {f['title']} ({f['file_path']}:{f['line']}) — {f['description']}"
        for f in findings
    )
    source_context = _read_source_context(Path(state["path"]).resolve(), findings)
    prompt = (
        "You are a security engineer. For the findings below, produce a single "
        "unified diff (git apply compatible, paths relative to repo root) that "
        "fixes them with the smallest possible change. Base the patch on the "
        "actual file content given — do not invent code that isn't shown. "
        "Output ONLY the diff, no explanation, no markdown fences.\n\n"
        f"Findings:\n{listing}\n\nFile contents:\n{source_context}"
    )
    try:
        diff = complete([{"role": "user", "content": prompt}], purpose="coding")
    except LLMUnavailable as exc:
        return {**state, "diff": "", "error": str(exc)}
    return {**state, "diff": _strip_markdown_fences(diff)}


def _fix_apply_node(state: FixState) -> FixState:
    return {**state, "applied": False, "committed": False, "test_output": ""}


def build_fix_graph():
    graph = StateGraph(FixState)
    graph.add_node("scan", _fix_scan_node)
    graph.add_node("patch", _fix_patch_node)
    graph.add_node("prepare", _fix_apply_node)
    graph.set_entry_point("scan")
    graph.add_edge("scan", "patch")
    graph.add_edge("patch", "prepare")
    graph.add_edge("prepare", END)
    return graph.compile()


_fix_graph = build_fix_graph()


def propose_fix(path: str) -> FixState:
    """Scan + propose a patch. Does not touch disk — see apply_fix for that."""
    return _fix_graph.invoke(
        {
            "path": path,
            "findings": [],
            "diff": "",
            "applied": False,
            "committed": False,
            "test_output": "",
            "error": None,
        }
    )


def apply_fix(path: str, diff: str, do_commit: bool) -> tuple[bool, bool, str, str | None]:
    """Applies an already-proposed diff, optionally runs tests + commits.

    Returns (applied, committed, test_output, error).
    """
    repo_path = Path(path).resolve()
    try:
        git_apply_patch(repo_path, diff)
    except ToolError as exc:
        return False, False, "", str(exc)

    passed, output = run_tests(repo_path)
    if not passed:
        return True, False, output, "tests failed after applying patch — not committing"

    if do_commit:
        try:
            git_commit(repo_path, "fix: apply Es-suggested security patch")
        except Exception as exc:  # noqa: BLE001
            return True, False, output, f"tests passed but commit failed: {exc}"
        return True, True, output, None

    return True, False, output, None
