import threading
from pathlib import Path

import httpx
import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from api.correlate import correlate_findings
from cli import launch as launch_lifecycle, server as server_lifecycle
from cli.client import BASE_URL, SCAN_TIMEOUT, get as http_get, post
from cli.report import render_markdown, write_report

app = typer.Typer(add_completion=False, help="Scorpion v2 — local AI security platform CLI")
console = Console()

# Plain ASCII only (no box-drawing/emoji) — a real UnicodeEncodeError on
# Windows' legacy cp1252 console is what killed the earlier checkmark/cross
# symbols elsewhere in this CLI, and a banner is the last place we want a
# crash before the tool has even started.
BANNER = r"""
  _____  _____ ____  _____  _____ _____ ____  _   _
 / ____|/ ____/ __ \|  __ \|  __ \_   _/ __ \| \ | |
| (___ | |   | |  | | |__) | |__) || || |  | |  \| |
 \___ \| |   | |  | |  _  /|  ___/ | || |  | | . ` |
 ____) | |___| |__| | | \ \| |    _| || |__| | |\  |
|_____/ \_____\____/|_|  \_\_|   |_____\____/|_| \_|
                   v2 -- local AI security platform
"""


def _connection_error_hint() -> None:
    console.print(
        f"[red]Could not reach the Scorpion Agent Core at {BASE_URL}.[/red]\n"
        "Start it: [bold]scorpion serve[/bold]"
    )


def _ensure_target_verified(target: str, self_attest: str | None) -> None:
    """Shared by every command that scans a target: checks scope, and if
    it isn't verified, self-attests (non-interactively if --self-attest
    was given, otherwise an interactive prompt). Raises typer.Exit(1) if
    the user declines."""
    status = post("/v1/targets/status", {"target": target})
    if status["status"] == "verified":
        return

    statement = self_attest
    if not statement:
        console.print(
            f"[yellow]Target '{target}' isn't verified — no one has technically proven "
            "control over it.[/yellow]"
        )
        if not typer.confirm(
            f"Do you personally attest that you own or are explicitly authorized to test "
            f"'{target}'? This is logged against the target, not a blanket approval."
        ):
            console.print(
                "Not scanning. For a stronger, provable verification instead, use "
                "[bold]scorpion verify-target[/bold] (file-token method)."
            )
            raise typer.Exit(1)
        statement = typer.prompt(
            'Briefly state your authorization (e.g. "I own this domain", "bug bounty program X")'
        )

    attest = post("/v1/targets/self-attest", {"target": target, "statement": statement})
    console.print(f"[dim]Recorded: {attest['verification_method']}[/dim]")


def _run_tracked(key: str, description: str, func):
    """Runs `func` (a zero-arg callable performing the actual blocking
    POST) in a background thread while polling /v1/scan/progress (keyed
    by `key` — a target string for scan/scan-api, a local path for
    analyze/fix, since scan_status is just keyed by arbitrary string) to
    show a live spinner with the current server-side stage and elapsed
    time. Every long-running command uses this instead of blocking
    silently — found the hard way that a terminal showing nothing for
    minutes is indistinguishable from a hang.

    Re-raises whatever exception `func` raised, on the main thread, so
    each caller's existing httpx exception handling around the call
    keeps working unchanged.
    """
    outcome: dict = {}

    def _run() -> None:
        try:
            outcome["result"] = func()
        except Exception as exc:  # noqa: BLE001 - re-raised on the main thread below
            outcome["error"] = exc

    worker = threading.Thread(target=_run, daemon=True)
    worker.start()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task(description, total=None)
        while worker.is_alive():
            try:
                info = http_get("/v1/scan/progress", params={"target": key})
            except Exception:  # noqa: BLE001 - progress polling is best-effort, never fatal
                info = {"running": False}
            if info.get("running"):
                progress.update(
                    task,
                    description=(
                        f"{info['stage']} (stage {info['stage_index']}/{info['stage_total']}, "
                        f"{info['elapsed_seconds']:.0f}s)"
                    ),
                )
            else:
                progress.update(task, description=description)
            worker.join(timeout=0.5)

    if "error" in outcome:
        raise outcome["error"]
    return outcome["result"]


@app.command()
def launch() -> None:
    """Start everything: checks Docker, brings up Postgres, builds the ffuf
    image if missing, then starts the Agent Core. Safe to re-run — every
    step is idempotent. This is the one command to run each time you sit
    down to use Scorpion."""
    console.print(f"[bold red]{BANNER}[/bold red]")
    for ok, message in launch_lifecycle.launch():
        console.print(f"[green]OK  {message}[/green]" if ok else f"[red]FAIL {message}[/red]")
        if not ok:
            raise typer.Exit(1)


@app.command()
def serve(
    foreground: bool = typer.Option(
        False, "--foreground", help="Run attached to this terminal instead of detached in the background"
    ),
) -> None:
    """Start the Agent Core. Detached and tracked by PID file unless --foreground."""
    if foreground:
        server_lifecycle.start(foreground=True)
        return
    ok, message = server_lifecycle.start()
    console.print(f"[green]{message}[/green]" if ok else f"[yellow]{message}[/yellow]")


@app.command()
def stop() -> None:
    """Stop a background Agent Core started with `scorpion serve`."""
    ok, message = server_lifecycle.stop()
    console.print(f"[green]{message}[/green]" if ok else f"[yellow]{message}[/yellow]")


@app.command()
def status() -> None:
    """Check whether the Agent Core is running."""
    console.print(server_lifecycle.status())


@app.command()
def analyze(
    path: str = typer.Argument(..., help="Local path to analyze"),
    report: str = typer.Option(
        None, "--report", help="Also write the findings to a Markdown report at this path"
    ),
) -> None:
    """Static security review of local code (Coding Agent, no network activity)."""
    try:
        result = _run_tracked(path, "Running semgrep...", lambda: post("/v1/analyze", {"path": path}))
    except httpx.ConnectError:
        _connection_error_hint()
        raise typer.Exit(1)
    except httpx.HTTPStatusError as exc:
        console.print(f"[red]Agent Core error: {exc.response.text}[/red]")
        raise typer.Exit(1)

    if result.get("error"):
        console.print(f"[yellow]Warning: {result['error']}[/yellow]")

    findings = correlate_findings(result["findings"])
    if not findings:
        console.print("[green]No findings.[/green]")
    else:
        table = Table(title=f"{len(findings)} finding(s)")
        table.add_column("Severity")
        table.add_column("Rule")
        table.add_column("Location")
        table.add_column("Description")
        for f in findings:
            loc = f"{f['file_path']}:{f['line']}" if f.get("file_path") else "-"
            table.add_row(f["severity"], f["title"], loc, f["description"][:80])
        console.print(table)

    console.print("\n[bold]Summary[/bold]")
    console.print(result["summary"])

    if report:
        content = render_markdown("Scorpion Code Analysis Report", path, findings, result["summary"])
        out = write_report(report, content)
        console.print(f"[dim]Report written to {out}[/dim]")


@app.command()
def fix(
    path: str = typer.Argument(..., help="Local path (git repo) to fix"),
    apply: bool = typer.Option(False, "--apply", help="Write the proposed patch to disk and run tests"),
    commit: bool = typer.Option(False, "--commit", help="Commit if tests pass after --apply. Ignored without --apply."),
) -> None:
    """Find issues and propose a patch (Coding Agent). Nothing touches disk without --apply."""
    try:
        proposal = _run_tracked(
            path, "Analyzing and generating patch...", lambda: post("/v1/fix/propose", {"path": path})
        )
    except httpx.ConnectError:
        _connection_error_hint()
        raise typer.Exit(1)
    except httpx.HTTPStatusError as exc:
        console.print(f"[red]Agent Core error: {exc.response.text}[/red]")
        raise typer.Exit(1)

    if proposal.get("error"):
        console.print(f"[red]{proposal['error']}[/red]")
        raise typer.Exit(1)

    if not proposal["diff"]:
        console.print("[green]No findings, nothing to patch.[/green]")
        return

    console.print("[bold]Proposed patch[/bold]")
    console.print(proposal["diff"])

    if not apply:
        console.print("\n[dim]Re-run with --apply to write this to disk and run tests.[/dim]")
        return

    apply_result = _run_tracked(
        path,
        "Applying patch and running tests...",
        lambda: post("/v1/fix/apply", {"path": path, "diff": proposal["diff"], "commit": commit}),
    )
    if apply_result.get("error"):
        console.print(f"[yellow]{apply_result['error']}[/yellow]")
    console.print(f"Applied: {apply_result['applied']}  Committed: {apply_result['committed']}")
    console.print(apply_result["test_output"])


@app.command()
def scan(
    target: str = typer.Argument(..., help="Domain/IP/host to scan"),
    self_attest: str = typer.Option(
        None,
        "--self-attest",
        help="Non-interactively attest ownership/authorization with this statement "
        "(skips the prompt below; still the weakest, logged verification method)",
    ),
    report: str = typer.Option(
        None, "--report", help="Also write the findings to a Markdown report at this path"
    ),
) -> None:
    """Orchestrator-driven recon + active scan chain (Pentest Agent).

    Active stages only run against targets verified in scope.
    `localhost`/private IPs auto-verify. Anything else prompts for
    self-attestation (weak, logged) or use `scorpion verify-target` first
    for a real, provable verification.
    """
    try:
        _ensure_target_verified(target, self_attest)
    except httpx.ConnectError:
        _connection_error_hint()
        raise typer.Exit(1)

    console.print(
        "[dim]Running the full pipeline — against a real site this can take several "
        "minutes (nuclei alone can run ~3000 requests). Live stage progress below.[/dim]"
    )

    try:
        result = _run_tracked(
            target, "Starting scan...", lambda: post("/v1/scan", {"target": target}, timeout=SCAN_TIMEOUT)
        )
    except httpx.ConnectError:
        _connection_error_hint()
        raise typer.Exit(1)
    except httpx.ReadTimeout:
        console.print(
            f"[red]No response after {SCAN_TIMEOUT}s.[/red] The scan may still be running "
            "server-side — the Agent Core doesn't cancel work just because the CLI stopped "
            "waiting. Check its findings later rather than re-running immediately."
        )
        raise typer.Exit(1)
    except httpx.HTTPStatusError as exc:
        console.print(f"[red]Agent Core error: {exc.response.text}[/red]")
        raise typer.Exit(1)

    for w in result["warnings"]:
        console.print(f"[yellow]{w}[/yellow]")

    findings = correlate_findings(result["findings"])
    if not findings:
        console.print("[green]No findings.[/green]")
    else:
        table = Table(title=f"{len(findings)} finding(s)")
        table.add_column("Tool")
        table.add_column("Severity")
        table.add_column("Title")
        table.add_column("Description")
        for f in findings:
            table.add_row(f["source_tool"], f["severity"], f["title"], f["description"][:80])
        console.print(table)

    console.print("\n[bold]Summary[/bold]")
    console.print(result["summary"])

    if report:
        content = render_markdown(
            "Scorpion Pentest Report",
            target,
            findings,
            result["summary"],
            warnings=result["warnings"],
            report_requirements=result.get("report_requirements"),
        )
        out = write_report(report, content)
        console.print(f"[dim]Report written to {out}[/dim]")


@app.command("scan-api")
def scan_api(
    target: str = typer.Argument(..., help="Domain/host this scan is scoped to (used for the scope gate)"),
    spec: str = typer.Option(..., "--spec", help="OpenAPI/Swagger definition — URL or local file path"),
    target_url: str = typer.Option(
        None, "--target-url", help="Override the API host if the spec's own base URL isn't directly reachable"
    ),
    auth_header: str = typer.Option(
        None, "--auth-header", help='Header injected into every request, e.g. "Authorization: Bearer <token>"'
    ),
    self_attest: str = typer.Option(
        None,
        "--self-attest",
        help="Non-interactively attest ownership/authorization with this statement",
    ),
    report: str = typer.Option(
        None, "--report", help="Also write the findings to a Markdown report at this path"
    ),
) -> None:
    """API-spec-driven scan (OWASP ZAP's zap-api-scan) — tests every
    endpoint/parameter an OpenAPI/Swagger definition declares, including
    authenticated ones via --auth-header. Reaches routes a crawl-based
    `scan` can never discover on its own: POST-only endpoints, JSON
    bodies, anything not linked from an HTML page."""
    try:
        _ensure_target_verified(target, self_attest)
    except httpx.ConnectError:
        _connection_error_hint()
        raise typer.Exit(1)

    try:
        result = _run_tracked(
            target,
            "Running zap-api-scan...",
            lambda: post(
                "/v1/scan-api",
                {"target": target, "spec": spec, "target_override": target_url, "auth_header": auth_header},
                timeout=SCAN_TIMEOUT,
            ),
        )
    except httpx.ConnectError:
        _connection_error_hint()
        raise typer.Exit(1)
    except httpx.HTTPStatusError as exc:
        console.print(f"[red]Agent Core error: {exc.response.text}[/red]")
        raise typer.Exit(1)

    for w in result["warnings"]:
        console.print(f"[yellow]{w}[/yellow]")

    findings = correlate_findings(result["findings"])
    if not findings:
        console.print("[green]No findings.[/green]")
    else:
        table = Table(title=f"{len(findings)} finding(s)")
        table.add_column("Tool")
        table.add_column("Severity")
        table.add_column("Title")
        table.add_column("Description")
        for f in findings:
            table.add_row(f["source_tool"], f["severity"], f["title"], f["description"][:80])
        console.print(table)

    console.print("\n[bold]Summary[/bold]")
    console.print(result["summary"])

    if report:
        content = render_markdown(
            "Scorpion API Scan Report",
            target,
            findings,
            result["summary"],
            warnings=result["warnings"],
            report_requirements=result.get("report_requirements"),
        )
        out = write_report(report, content)
        console.print(f"[dim]Report written to {out}[/dim]")


@app.command("verify-target")
def verify_target(
    target: str = typer.Argument(..., help="Domain/host to verify"),
    token: str = typer.Option(..., "--token", help="Token placed at https://<target>/.well-known/scorpion-auth.txt"),
) -> None:
    """Verify scope authorization via the file-token method before scanning a target you don't own."""
    try:
        result = post("/v1/targets/verify", {"target": target, "token": token})
    except httpx.ConnectError:
        _connection_error_hint()
        raise typer.Exit(1)

    if result.get("error"):
        console.print(f"[red]{result['error']}[/red]")
        raise typer.Exit(1)
    console.print(f"[green]{target} is now {result['status']} ({result['verification_method']})[/green]")


@app.command("authorize-sow")
def authorize_sow(
    target: str = typer.Argument(..., help="Domain/host the SOW authorizes (must be explicitly named in the document)"),
    sow_file: str = typer.Argument(..., help="Path to the Statement of Work document (plain text/Markdown)"),
) -> None:
    """Authorize a target from a real Statement of Work — the only path that
    can grant the stronger 'exploitation' tier (e.g. sqlmap confirming real
    impact, not just detecting injectability). An LLM reads the document and
    extracts only what it explicitly grants; ambiguous language never
    authorizes exploitation. Requires an LLM configured (SCORPION_CODING_MODELS)."""
    try:
        sow_text = Path(sow_file).read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        console.print(f"[red]Could not read {sow_file}: {exc}[/red]")
        raise typer.Exit(1)

    try:
        result = post("/v1/targets/authorize-sow", {"target": target, "sow_text": sow_text})
    except httpx.ConnectError:
        _connection_error_hint()
        raise typer.Exit(1)

    if result.get("error"):
        console.print(f"[red]{result['error']}[/red]")
        raise typer.Exit(1)

    console.print(f"[green]{target} is now {result['status']} ({result['verification_method']})[/green]")
    if result["exploitation_authorized"]:
        console.print(
            "[yellow]Exploitation authorized — sqlmap will confirm real impact "
            "(database enumeration) where injection is found, not just detect it.[/yellow]"
        )
    else:
        console.print(
            "[dim]Exploitation not authorized by this SOW — active-scan tools stay at "
            "detection-only.[/dim]"
        )


if __name__ == "__main__":
    app()
