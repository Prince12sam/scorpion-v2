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
        "semgrep", "scan", "--config=auto", "--json", "--quiet", "/src",
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=settings.semgrep_timeout_seconds)
    except FileNotFoundError as exc:
        raise ToolError("docker CLI not found — Docker Desktop must be installed and running") from exc
    except subprocess.TimeoutExpired as exc:
        raise ToolError(f"semgrep timed out after {settings.semgrep_timeout_seconds}s") from exc
    result.stdout = result.stdout or ""
    result.stderr = result.stderr or ""

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
        timeout=settings.test_run_timeout_seconds,
    )
    return result.returncode == 0, ((result.stdout or "") + (result.stderr or ""))[-4000:]


def git_commit(repo_path: Path, message: str) -> None:
    subprocess.run(["git", "add", "-A"], cwd=repo_path, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", message], cwd=repo_path, check=True, capture_output=True, text=True)


def _run_docker(cmd: list[str], tool_name: str, timeout: int | None = None) -> subprocess.CompletedProcess:
    timeout = timeout if timeout is not None else settings.tool_timeout_seconds
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError as exc:
        raise ToolError("docker CLI not found — Docker Desktop must be installed and running") from exc
    except subprocess.TimeoutExpired as exc:
        raise ToolError(f"{tool_name} timed out after {timeout}s") from exc
    # Under concurrent docker invocations (multiple scans in flight at once,
    # each spawning subprocesses from FastAPI's threadpool), stdout/stderr
    # have been observed coming back None despite capture_output=True/
    # text=True, which should guarantee a str — never trust it blindly.
    result.stdout = result.stdout or ""
    result.stderr = result.stderr or ""
    return result


def _parse_json_lines(text: str) -> list[dict]:
    rows = []
    for line in text.strip().splitlines():
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def run_httpx(host: str) -> list[dict]:
    """HTTP fingerprinting via projectdiscovery/httpx, containerized."""
    cmd = [
        "docker", "run", "--rm",
        settings.httpx_docker_image,
        "-u", host, "-silent", "-json", "-status-code", "-title", "-tech-detect", "-server",
    ]
    result = _run_docker(cmd, "httpx")
    if result.returncode != 0 and not result.stdout.strip():
        raise ToolError(f"httpx failed (exit {result.returncode}): {result.stderr[-2000:]}")

    findings = []
    for line in result.stdout.strip().splitlines():
        if not line.strip():
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        status = r.get("status_code")
        title = r.get("title", "")
        tech = ", ".join(r.get("tech", []) or [])
        findings.append(
            {
                "source_tool": "httpx",
                "severity": "info",
                "title": f"HTTP {status} — {r.get('url', host)}",
                "description": f"title={title!r} server={r.get('webserver', '')!r} tech={tech}",
                "file_path": None,
                "line": None,
            }
        )
    return findings


def run_nmap(host: str, top_ports: int = 100, ports: str | None = None) -> list[dict]:
    """TCP port scan via instrumentisto/nmap, containerized.

    -Pn skips host discovery: ICMP from a container to the Docker Desktop
    host/VM network is frequently filtered, and skipping it is standard
    practice when the target is already known to be up. Pass `ports` (nmap
    -p syntax, e.g. "8080" or "1-1000") to scan a specific range instead of
    the top N most common ports.
    """
    port_arg = f"-p{ports}" if ports else f"--top-ports={top_ports}"
    cmd = [
        "docker", "run", "--rm",
        settings.nmap_docker_image,
        "nmap", "-Pn", "-T4", port_arg, "-oX", "-", host,
    ]
    result = _run_docker(cmd, "nmap")
    if result.returncode != 0:
        raise ToolError(f"nmap failed (exit {result.returncode}): {result.stderr[-2000:]}")

    return _parse_nmap_xml(result.stdout, host)


def _parse_nmap_xml(xml_text: str, host: str) -> list[dict]:
    import xml.etree.ElementTree as ET

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ToolError(f"could not parse nmap output: {exc}") from exc

    findings = []
    for port_el in root.findall(".//port"):
        state_el = port_el.find("state")
        if state_el is None or state_el.get("state") != "open":
            continue
        service_el = port_el.find("service")
        service = service_el.get("name", "") if service_el is not None else ""
        product = service_el.get("product", "") if service_el is not None else ""
        portid = port_el.get("portid")
        protocol = port_el.get("protocol")
        findings.append(
            {
                "source_tool": "nmap",
                "severity": "info",
                "title": f"open {protocol}/{portid} ({service})",
                "description": f"{product}".strip() or f"{service} on {host}",
                "file_path": None,
                "line": None,
            }
        )
    return findings


def run_subfinder(domain: str) -> list[dict]:
    """Passive subdomain enumeration via projectdiscovery/subfinder.

    Queries public passive sources (certificate transparency logs, etc.) —
    it never sends a request to the target's own infrastructure, which is
    why it's classified passive-recon even for domains only weakly verified.
    """
    cmd = [
        "docker", "run", "--rm",
        settings.subfinder_docker_image,
        "-d", domain, "-silent", "-json",
    ]
    result = _run_docker(cmd, "subfinder")
    if result.returncode != 0 and not result.stdout.strip():
        raise ToolError(f"subfinder failed (exit {result.returncode}): {result.stderr[-2000:]}")

    findings = []
    for r in _parse_json_lines(result.stdout):
        host = r.get("host")
        if not host:
            continue
        findings.append(
            {
                "source_tool": "subfinder",
                "severity": "info",
                "title": f"subdomain: {host}",
                "description": f"source: {r.get('source', '')}",
                "file_path": None,
                "line": None,
            }
        )
    return findings


def run_katana(url: str) -> list[dict]:
    """Web crawl via projectdiscovery/katana — read-only GET requests only,
    same passive-recon classification as httpx's single-page fingerprint."""
    cmd = [
        "docker", "run", "--rm",
        settings.katana_docker_image,
        "-u", url, "-silent", "-jsonl", "-depth=2",
    ]
    result = _run_docker(cmd, "katana")
    if result.returncode != 0 and not result.stdout.strip():
        raise ToolError(f"katana failed (exit {result.returncode}): {result.stderr[-2000:]}")

    findings = []
    for r in _parse_json_lines(result.stdout):
        endpoint = (r.get("request") or {}).get("endpoint") or r.get("url")
        if not endpoint:
            continue
        status = (r.get("response") or {}).get("status_code")
        findings.append(
            {
                "source_tool": "katana",
                "severity": "info",
                "title": f"crawled: {endpoint}",
                "description": f"status={status}" if status else "",
                "file_path": None,
                "line": None,
            }
        )
    return findings


def run_nuclei(url: str) -> list[dict]:
    """Template-based vulnerability scan via projectdiscovery/nuclei.

    Active-scan: some templates send exploit-style payloads, not just reads.
    Template cache is kept in named Docker volumes so only the first run
    per machine pays the download cost.
    """
    cmd = [
        "docker", "run", "--rm",
        "-v", "es_nuclei_config:/root/.config/nuclei",
        "-v", "es_nuclei_cache:/root/.cache/nuclei",
        settings.nuclei_docker_image,
        "-u", url, "-silent", "-jsonl",
    ]
    result = _run_docker(cmd, "nuclei", timeout=settings.nuclei_timeout_seconds)
    if result.returncode != 0 and not result.stdout.strip():
        raise ToolError(f"nuclei failed (exit {result.returncode}): {result.stderr[-2000:]}")

    findings = []
    for r in _parse_json_lines(result.stdout):
        info = r.get("info", {}) or {}
        findings.append(
            {
                "source_tool": "nuclei",
                "severity": info.get("severity", "info").lower(),
                "title": r.get("template-id", info.get("name", "nuclei-finding")),
                "description": f"{info.get('name', '')} @ {r.get('matched-at', url)}",
                "file_path": None,
                "line": None,
            }
        )
    return findings


def run_ffuf(url: str) -> list[dict]:
    """Content/path discovery via a locally-built ffuf image (no official
    Docker Hub image exists — see docker/tools/ffuf/Dockerfile). Active-scan:
    sends a request per wordlist entry."""
    target = url.rstrip("/") + "/FUZZ"
    wordlist_path = Path(settings.ffuf_wordlist_path).resolve()
    if not wordlist_path.exists():
        raise ToolError(f"ffuf wordlist not found: {wordlist_path}")

    cmd = [
        "docker", "run", "--rm",
        "-v", f"{wordlist_path}:/wordlist.txt:ro",
        settings.ffuf_docker_image,
        "-u", target, "-w", "/wordlist.txt", "-of", "json", "-o", "/dev/stdout", "-s",
    ]
    result = _run_docker(cmd, "ffuf")
    if result.returncode != 0:
        raise ToolError(f"ffuf failed (exit {result.returncode}): {result.stderr[-2000:]}")

    # -s (silent) still prints each matched keyword as a plain line before
    # the final JSON blob written to -o; the JSON itself always starts at
    # the first '{'.
    json_start = result.stdout.find("{")
    if json_start == -1:
        raise ToolError(f"could not find JSON in ffuf output: {result.stdout[-2000:]}")
    try:
        data = json.loads(result.stdout[json_start:])
    except json.JSONDecodeError as exc:
        raise ToolError(f"could not parse ffuf output: {result.stderr[-2000:]}") from exc

    findings = []
    for r in data.get("results", []):
        findings.append(
            {
                "source_tool": "ffuf",
                "severity": "info",
                "title": f"found: {r.get('url', '')}",
                "description": f"status={r.get('status')} length={r.get('length')}",
                "file_path": None,
                "line": None,
            }
        )
    return findings


def run_dalfox(url: str) -> list[dict]:
    """XSS scan via hahwul/dalfox. Active-scan: injects payloads."""
    cmd = [
        "docker", "run", "--rm",
        settings.dalfox_docker_image,
        "./dalfox", "url", "--url", url, "--silence", "--format", "json",
    ]
    result = _run_docker(cmd, "dalfox")
    if result.returncode != 0 and not result.stdout.strip():
        raise ToolError(f"dalfox failed (exit {result.returncode}): {result.stderr[-2000:]}")

    try:
        data = json.loads(result.stdout) if result.stdout.strip() else {}
    except json.JSONDecodeError as exc:
        raise ToolError(f"could not parse dalfox output: {result.stderr[-2000:]}") from exc

    findings = []
    for r in data.get("findings", []) or []:
        findings.append(
            {
                "source_tool": "dalfox",
                "severity": (r.get("type", "info") or "info").lower(),
                "title": f"XSS: {r.get('param', 'unknown param')}",
                "description": r.get("evidence", r.get("poc", "")),
                "file_path": None,
                "line": None,
            }
        )
    return findings


def run_sqlmap(url: str) -> list[dict]:
    """SQL injection test via googlesky/sqlmap. Active-scan: injects
    payloads into request parameters — never run against a target without
    an explicit, verified active-scan authorization."""
    cmd = [
        "docker", "run", "--rm",
        settings.sqlmap_docker_image,
        "-u", url, "--batch", "--level=1", "--risk=1",
    ]
    result = _run_docker(cmd, "sqlmap", timeout=settings.nuclei_timeout_seconds)
    if result.returncode not in (0, 1):
        raise ToolError(f"sqlmap failed (exit {result.returncode}): {result.stderr[-2000:]}")

    findings = []
    output = result.stdout
    if "parameter" in output.lower() and "is vulnerable" in output.lower():
        for line in output.splitlines():
            if "vulnerable" in line.lower():
                findings.append(
                    {
                        "source_tool": "sqlmap",
                        "severity": "error",
                        "title": f"possible SQL injection @ {url}",
                        "description": line.strip(),
                        "file_path": None,
                        "line": None,
                    }
                )
    return findings
