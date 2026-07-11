import json
import subprocess
from pathlib import Path

from api.config import settings


class ToolError(Exception):
    pass


def run_semgrep(path: Path) -> list[dict]:
    """Run semgrep against a local path, sandboxed in a container.

    Semgrep has no native Windows build, and containerizing it also matches
    docs/SECURITY_AND_AUTHORIZATION.md's sandboxing rule for every external
    tool the Tool Orchestrator runs.
    """
    abs_path = path.resolve()
    if not abs_path.exists():
        raise ToolError(f"path does not exist: {abs_path}")

    cmd = [
        "docker", "run", "--rm",
        "-v", f"{abs_path}:/src:ro",
        settings.semgrep_docker_image,
        "semgrep", "scan", "--config=auto", "--json", "--quiet", "--metrics=off", "/src",
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except FileNotFoundError as exc:
        raise ToolError("docker CLI not found — Docker Desktop must be installed and running") from exc
    except subprocess.TimeoutExpired as exc:
        raise ToolError("semgrep timed out after 300s") from exc

    # semgrep exits 1 when it finds issues — that's not a tool failure.
    if result.returncode not in (0, 1):
        raise ToolError(f"semgrep failed (exit {result.returncode}): {result.stderr[-2000:]}")

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ToolError(f"could not parse semgrep output: {result.stderr[-2000:]}") from exc

    findings = []
    for r in data.get("results", []):
        extra = r.get("extra", {})
        findings.append(
            {
                "source_tool": "semgrep",
                "severity": extra.get("severity", "info").lower(),
                "title": r.get("check_id", "semgrep-finding"),
                "description": extra.get("message", ""),
                "file_path": r.get("path"),
                "line": (r.get("start") or {}).get("line"),
            }
        )
    return findings


def git_apply_patch(repo_path: Path, diff_text: str) -> None:
    result = subprocess.run(
        ["git", "apply", "--whitespace=nowarn", "-"],
        cwd=repo_path,
        input=diff_text,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise ToolError(f"git apply failed: {result.stderr.strip()}")


def run_tests(repo_path: Path) -> tuple[bool, str]:
    result = subprocess.run(
        ["python", "-m", "pytest", "-q"],
        cwd=repo_path,
        capture_output=True,
        text=True,
        timeout=600,
    )
    return result.returncode == 0, (result.stdout + result.stderr)[-4000:]


def git_commit(repo_path: Path, message: str) -> None:
    subprocess.run(["git", "add", "-A"], cwd=repo_path, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", message], cwd=repo_path, check=True, capture_output=True, text=True)
