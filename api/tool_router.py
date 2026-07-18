import json
import re
import subprocess
import sys
import tempfile
import uuid
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
    result = _run_docker(cmd, "semgrep", timeout=settings.semgrep_timeout_seconds)

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
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode != 0:
        raise ToolError(f"git apply failed: {result.stderr.strip()}")


def run_tests(repo_path: Path) -> tuple[bool, str]:
    result = subprocess.run(
        # sys.executable, not the literal "python": that name isn't
        # guaranteed on PATH (many Linux distros only ship "python3"), and
        # this also guarantees the same interpreter/venv Scorpion itself runs in.
        [sys.executable, "-m", "pytest", "-q"],
        cwd=repo_path,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=settings.test_run_timeout_seconds,
    )
    return result.returncode == 0, ((result.stdout or "") + (result.stderr or ""))[-4000:]


def git_commit(repo_path: Path, message: str) -> None:
    subprocess.run(["git", "add", "-A"], cwd=repo_path, check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", message],
        cwd=repo_path,
        check=True,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
    )


def _run_docker(
    cmd: list[str], tool_name: str, timeout: int | None = None, stdin_text: str | None = None
) -> subprocess.CompletedProcess:
    """Every caller here builds cmd as ["docker", "run", "--rm", ...]. This
    inserts an explicit --name so a timeout can actually stop the container.

    Killing the local `docker run` client process (what subprocess.run's
    timeout does by default) does NOT stop the container itself — it keeps
    running server-side in Docker, unbounded, still hitting whatever target
    it was pointed at. Found this the hard way: a dalfox run against a real
    site outlived its 180s timeout by several minutes because nothing ever
    told Docker to stop it.
    """
    timeout = timeout if timeout is not None else settings.tool_timeout_seconds
    container_name = f"scorpion-{tool_name}-{uuid.uuid4().hex[:12]}"
    named_cmd = cmd[:3] + ["--name", container_name] + cmd[3:]
    # Never let this inherit the calling process's own stdin. subprocess.run
    # only sets stdin=PIPE when input= is not None, so every caller without
    # stdin_text (everything except httpx's batch mode) would otherwise
    # inherit whatever fd this process happens to have. That's harmless
    # under a normal `scorpion serve` (its own stdin is explicitly DEVNULL —
    # see cli/server.py) but a real hang risk under `serve --foreground`
    # (inherits a live terminal) or any ad-hoc script: confirmed sqlmap's
    # confirm_impact mode hang the full configured timeout on an
    # interactive prompt --batch should have auto-answered, once stdin
    # wasn't deterministically closed.
    stdin_kwargs = {"input": stdin_text} if stdin_text is not None else {"stdin": subprocess.DEVNULL}
    try:
        result = subprocess.run(
            named_cmd, capture_output=True, encoding="utf-8", errors="replace", timeout=timeout, **stdin_kwargs
        )
    except FileNotFoundError as exc:
        raise ToolError("docker CLI not found — Docker Desktop must be installed and running") from exc
    except subprocess.TimeoutExpired as exc:
        # Best-effort cleanup only — this must never itself hang the request.
        # `docker kill` with no timeout of its own did exactly that under
        # heavy concurrent load: the outer timeout fired, but the cleanup
        # call blocked for close to an hour instead of the ToolError below
        # ever getting raised.
        try:
            subprocess.run(["docker", "kill", container_name], capture_output=True, timeout=15)
        except (subprocess.TimeoutExpired, OSError):
            pass
        raise ToolError(f"{tool_name} timed out after {timeout}s (container stop attempted)") from exc
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


def run_httpx(hosts: str | list[str]) -> list[dict]:
    """HTTP fingerprinting via projectdiscovery/httpx, containerized.

    Accepts one host or a batch — batching every candidate host (the root
    target plus everything subfinder discovered) into a single container
    via stdin is httpx's own documented usage (`cat hosts.txt | httpx`) and
    is far cheaper than spinning up one container per host to find out
    which ones are actually alive.
    """
    host_list = [hosts] if isinstance(hosts, str) else hosts
    stdin_text = "\n".join(host_list) + "\n"
    cmd = [
        "docker", "run", "--rm", "-i",
        settings.httpx_docker_image,
        "-silent", "-json", "-status-code", "-title", "-tech-detect", "-server",
    ]
    result = _run_docker(cmd, "httpx", stdin_text=stdin_text)
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
        url = r.get("url", "")
        findings.append(
            {
                "source_tool": "httpx",
                "severity": "info",
                "title": f"HTTP {status} — {url or host_list[0]}",
                "description": f"title={title!r} server={r.get('webserver', '')!r} tech={tech}",
                "file_path": None,
                "line": None,
                # The live URL this host actually responded on — used to feed
                # the rest of the pipeline per discovered/live host, not just
                # kept as display text like the other fields here.
                "live_url": url or None,
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
                # Bare hostname for the orchestrator to feed into the
                # liveness probe / per-host pipeline — see run_httpx's
                # "live_url" for the same pattern on the other end of it.
                "host": host,
            }
        )
    return findings


_AMASS_FQDN_RE = re.compile(r"([\w.-]+) \(FQDN\)")


def _parse_amass_output(text: str, domain: str) -> list[dict]:
    hosts = set()
    for match in _AMASS_FQDN_RE.finditer(text):
        name = match.group(1)
        # Genuine subdomains only — the root domain itself shows up
        # constantly as a graph node (e.g. as the source of every ns_record
        # line) and isn't something amass "discovered", it's the target.
        if name != domain and name.endswith(f".{domain}"):
            hosts.add(name)

    findings = []
    for host in sorted(hosts):
        findings.append(
            {
                "source_tool": "amass",
                "severity": "info",
                "title": f"subdomain: {host}",
                "description": "source: amass (passive enumeration)",
                "file_path": None,
                "line": None,
                "host": host,
            }
        )
    return findings


def run_amass(domain: str) -> list[dict]:
    """Passive subdomain enumeration via OWASP Amass (caffix/amass) — a
    different data source mix than subfinder (its own DNS graph analysis
    plus a different set of passive sources), so it often surfaces
    subdomains subfinder doesn't. `amass enum`'s own -active/-brute flags
    (zone transfers, cert grabs against the target's own infrastructure,
    brute-force DNS) are never passed here — same passive-recon
    classification as subfinder for that reason.

    Unlike subfinder (JSON on stdout), amass only writes structured output
    to a file inside -dir, so this needs the same mounted-volume pattern
    as ZAP's packaged scans.
    """
    with tempfile.TemporaryDirectory() as tmp_dir:
        amass_minutes = max(1, settings.amass_timeout_seconds // 60)
        cmd = [
            "docker", "run", "--rm",
            "-v", f"{Path(tmp_dir).resolve()}:/amass_out",
            settings.amass_docker_image,
            "enum", "-d", domain, "-dir", "/amass_out", "-timeout", str(amass_minutes),
        ]
        result = _run_docker(cmd, "amass", timeout=settings.amass_timeout_seconds)
        output_path = Path(tmp_dir) / "amass.txt"
        if result.returncode != 0 and not output_path.exists():
            raise ToolError(f"amass failed (exit {result.returncode}): {result.stderr[-2000:]}")
        if not output_path.exists():
            return []

        return _parse_amass_output(output_path.read_text(encoding="utf-8", errors="replace"), domain)


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


def _parse_sqlmap_impact(output: str, url: str) -> list[dict]:
    """Parses the extra output confirm_impact=True's flags produce.
    Enumeration only (database names, current DB, version banner) — never
    data extraction, which stays a separate, even-more-explicit capability
    this doesn't implement."""
    findings = []

    current_db = re.search(r"current database:\s*'([^']*)'", output, re.IGNORECASE)
    if current_db:
        findings.append(
            {
                "source_tool": "sqlmap",
                "severity": "high",
                "title": f"confirmed impact: current database — {current_db.group(1)}",
                "description": f"enumerated via the confirmed injection point @ {url} (no data extracted)",
                "file_path": None,
                "line": None,
            }
        )

    banner = re.search(r"banner:\s*'([^']*)'", output, re.IGNORECASE)
    if banner:
        findings.append(
            {
                "source_tool": "sqlmap",
                "severity": "high",
                "title": f"confirmed impact: DBMS banner — {banner.group(1)}",
                "description": f"version banner retrieved via the confirmed injection point @ {url}",
                "file_path": None,
                "line": None,
            }
        )

    dbs = re.search(r"available databases \[\d+\]:\s*((?:\n\[\*\] .+)+)", output)
    if dbs:
        names = [line.strip("[*] \r") for line in dbs.group(1).strip().splitlines()]
        findings.append(
            {
                "source_tool": "sqlmap",
                "severity": "high",
                "title": f"confirmed impact: {len(names)} database(s) enumerated",
                "description": f"available databases: {', '.join(names)} (enumeration only, no data extracted)",
                "file_path": None,
                "line": None,
            }
        )

    return findings


def run_sqlmap(url: str, confirm_impact: bool = False) -> list[dict]:
    """SQL injection test via googlesky/sqlmap. Active-scan by default:
    injects payloads to detect injectability only — never run against a
    target without an explicit, verified active-scan authorization.

    confirm_impact=True additionally enumerates the active database name,
    DBMS version banner, and available database names as proof of real
    impact. The caller (api/orchestrator.py) only ever passes this True
    after checking the target has the stronger "exploitation" scope tier
    (api/scope.py), which only a parsed SOW can grant — never self-attestation
    or file-token verification. Still no data extraction (--dump) or shell
    access, which stays a separate, even-more-explicit capability this
    doesn't implement.
    """
    extra_args = ["--dbs", "--current-db", "--banner"] if confirm_impact else []
    timeout = settings.sqlmap_confirm_impact_timeout_seconds if confirm_impact else settings.sqlmap_timeout_seconds
    cmd = [
        "docker", "run", "--rm",
        settings.sqlmap_docker_image,
        "-u", url, "--batch", "--level=1", "--risk=1", *extra_args,
    ]
    result = _run_docker(cmd, "sqlmap", timeout=timeout)
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

    if confirm_impact:
        findings.extend(_parse_sqlmap_impact(output, url))

    return findings


_ZAP_RISK_SEVERITY = {"0": "info", "1": "low", "2": "medium", "3": "high"}


def _parse_zap_report(report_path: Path, source_tool: str) -> list[dict]:
    try:
        data = json.loads(report_path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ToolError(f"could not parse {source_tool} report: {exc}") from exc

    findings = []
    for site in data.get("site", []) or []:
        for alert in site.get("alerts", []) or []:
            severity = _ZAP_RISK_SEVERITY.get(str(alert.get("riskcode", "")), "info")
            instances = alert.get("instances", []) or []
            sample_uri = instances[0].get("uri", "") if instances else ""
            findings.append(
                {
                    "source_tool": source_tool,
                    "severity": severity,
                    "title": alert.get("name") or alert.get("alert") or f"{source_tool}-finding",
                    "description": (
                        f"{alert.get('desc', '')} "
                        f"({len(instances)} instance(s), e.g. {sample_uri})"
                    ).strip(),
                    "file_path": None,
                    "line": None,
                }
            )
    return findings


def _run_zap_packaged_scan(
    url: str, script: str, source_tool: str, timeout: int, extra_args: list[str] | None = None
) -> list[dict]:
    """Shared runner for ZAP's packaged scan scripts (zap-baseline.py,
    zap-full-scan.py) — both take a target URL, spider/attack it, and can
    write a JSON report. The container is ephemeral (--rm), so the report
    has to land on a mounted host directory to survive past the run,
    unlike the other tools here which just read stdout.
    """
    with tempfile.TemporaryDirectory() as tmp_dir:
        report_name = "zap-report.json"
        cmd = [
            "docker", "run", "--rm",
            "-v", f"{Path(tmp_dir).resolve()}:/zap/wrk/:rw",
            settings.zap_docker_image,
            script, "-t", url, "-J", report_name,
            *(extra_args or []),
        ]
        result = _run_docker(cmd, source_tool, timeout=timeout)
        # zap-baseline.py/zap-full-scan.py use the exit code to signal alert
        # severity found (1 = warn present, 2 = fail present), not tool
        # failure — same non-zero-but-fine pattern as semgrep elsewhere here.
        report_path = Path(tmp_dir) / report_name
        if result.returncode not in (0, 1, 2) or not report_path.exists():
            raise ToolError(f"{source_tool} failed (exit {result.returncode}): {result.stderr[-2000:]}")

        return _parse_zap_report(report_path, source_tool)


def run_zap_baseline(url: str) -> list[dict]:
    """Passive scan via OWASP ZAP's zap-baseline.py — spiders the target
    briefly and passively analyzes traffic, no attack payloads sent.
    Same passive-recon classification as katana's crawl."""
    return _run_zap_packaged_scan(
        url, "zap-baseline.py", "zap-baseline", settings.zap_baseline_timeout_seconds
    )


def run_zap_full_scan(url: str) -> list[dict]:
    """Active scan via OWASP ZAP's zap-full-scan.py — spiders the target
    then actively attacks every discovered page/parameter. A different
    scanning engine than nuclei/dalfox/sqlmap, so it catches a different
    (overlapping but not identical) set of issues. Active-scan: sends
    exploit-style payloads, never run without verified authorization."""
    return _run_zap_packaged_scan(
        url, "zap-full-scan.py", "zap-full-scan", settings.zap_full_scan_timeout_seconds
    )


def run_zap_api_scan(
    spec: str, target_override: str | None = None, auth_header: str | None = None
) -> list[dict]:
    """API endpoint scan via OWASP ZAP's zap-api-scan.py — takes an
    OpenAPI/Swagger definition and tests every endpoint/parameter it
    declares, active-scan style. This is what reaches API routes a crawl
    (katana/zap-baseline/zap-full-scan) can never discover on its own:
    POST-only routes, JSON bodies, anything not linked from an HTML page.

    `spec` is a URL to fetch the definition from, or a local file path
    (mounted into the container read-only). `target_override` (-O) points
    requests at the actual reachable API host when the spec's own base
    URL isn't directly reachable from inside the container.
    `auth_header` (e.g. "Authorization: Bearer <token>") is injected into
    every request via a ZAP Replacer rule — most real API endpoints worth
    testing are behind auth, so without this most of the surface is
    untestable. Active-scan: sends real requests against every defined
    operation, never run without verified authorization.
    """
    volume_args: list[str] = []
    spec_arg = spec
    if not spec.startswith(("http://", "https://")):
        spec_path = Path(spec).resolve()
        if not spec_path.exists():
            raise ToolError(f"API spec file not found: {spec_path}")
        # Mounted under a path distinct from the report-output volume below
        # (both under /zap/wrk would collide: a file mount and a directory
        # mount at overlapping paths is fragile depending on Docker's mount
        # order).
        volume_args = ["-v", f"{spec_path}:/zap/spec/openapi.json:ro"]
        spec_arg = "/zap/spec/openapi.json"

    with tempfile.TemporaryDirectory() as tmp_dir:
        report_name = "zap-api-report.json"
        cmd = [
            "docker", "run", "--rm",
            *volume_args,
            "-v", f"{Path(tmp_dir).resolve()}:/zap/wrk/:rw",
            settings.zap_docker_image,
            "zap-api-scan.py", "-t", spec_arg, "-f", "openapi", "-J", report_name,
        ]
        if target_override:
            cmd += ["-O", target_override]
        if auth_header:
            header_name, _, header_value = auth_header.partition(":")
            cmd += [
                "-z",
                (
                    "-config replacer.full_list(0).description=auth "
                    "-config replacer.full_list(0).enabled=true "
                    "-config replacer.full_list(0).matchtype=REQ_HEADER "
                    f"-config replacer.full_list(0).matchstr={header_name.strip()} "
                    "-config replacer.full_list(0).regex=false "
                    f"-config replacer.full_list(0).replacement={header_value.strip()}"
                ),
            ]

        result = _run_docker(cmd, "zap-api-scan", timeout=settings.zap_api_scan_timeout_seconds)
        report_path = Path(tmp_dir) / report_name
        if result.returncode not in (0, 1, 2) or not report_path.exists():
            raise ToolError(f"zap-api-scan failed (exit {result.returncode}): {result.stderr[-2000:]}")

        return _parse_zap_report(report_path, "zap-api-scan")
