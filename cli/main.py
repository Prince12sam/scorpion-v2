import httpx
import typer
from rich.console import Console
from rich.table import Table

from cli.client import BASE_URL, post

app = typer.Typer(add_completion=False, help="Es — local AI security platform CLI (Phase 1: MVP)")
console = Console()


def _connection_error_hint() -> None:
    console.print(
        f"[red]Could not reach the Es Agent Core at {BASE_URL}.[/red]\n"
        "Start it first: [bold]uvicorn api.main:app --port 8731[/bold]"
    )


@app.command()
def analyze(path: str = typer.Argument(..., help="Local path to analyze")) -> None:
    """Static security review of local code (Coding Agent, no network activity)."""
    try:
        result = post("/v1/analyze", {"path": path})
    except httpx.ConnectError:
        _connection_error_hint()
        raise typer.Exit(1)
    except httpx.HTTPStatusError as exc:
        console.print(f"[red]Agent Core error: {exc.response.text}[/red]")
        raise typer.Exit(1)

    if result.get("error"):
        console.print(f"[yellow]Warning: {result['error']}[/yellow]")

    findings = result["findings"]
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


@app.command()
def fix(
    path: str = typer.Argument(..., help="Local path (git repo) to fix"),
    apply: bool = typer.Option(False, "--apply", help="Write the proposed patch to disk and run tests"),
    commit: bool = typer.Option(False, "--commit", help="Commit if tests pass after --apply. Ignored without --apply."),
) -> None:
    """Find issues and propose a patch (Coding Agent). Nothing touches disk without --apply."""
    try:
        proposal = post("/v1/fix/propose", {"path": path})
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

    apply_result = post("/v1/fix/apply", {"path": path, "diff": proposal["diff"], "commit": commit})
    if apply_result.get("error"):
        console.print(f"[yellow]{apply_result['error']}[/yellow]")
    console.print(f"Applied: {apply_result['applied']}  Committed: {apply_result['committed']}")
    console.print(apply_result["test_output"])


@app.command()
def scan(target: str = typer.Argument(..., help="Domain/IP/host to scan")) -> None:
    """Orchestrator-driven recon + active scan chain — NOT YET IMPLEMENTED (Phase 2)."""
    console.print(
        "[yellow]`es scan` depends on the Tool Orchestrator, which is Phase 2 "
        "work (see docs/ROADMAP.md). Not implemented yet.[/yellow]"
    )
    raise typer.Exit(1)


if __name__ == "__main__":
    app()
