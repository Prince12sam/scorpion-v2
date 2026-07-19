"""Markdown report rendering for `analyze --report` / `scan --report`.

Exists because CLI table output only lives in the scrollback — a real bug
bounty submission or client deliverable needs something durable and
shareable, not a terminal screenshot.
"""

from datetime import datetime, timezone
from pathlib import Path

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _severity_rank(finding: dict) -> int:
    return SEVERITY_ORDER.get(str(finding.get("severity", "")).lower(), 99)


def render_markdown(
    title: str,
    subject: str,
    findings: list[dict],
    summary: str,
    warnings: list[str] | None = None,
    report_requirements: list[str] | None = None,
) -> str:
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        f"# {title}",
        "",
        f"- **Target/path:** {subject}",
        f"- **Generated:** {generated}",
        f"- **Findings:** {len(findings)}",
        "",
    ]

    if report_requirements:
        # Surfaced verbatim from the SOW's own deliverable/reporting clause
        # (api/sow.py) — a checklist for whoever finalizes this report, not
        # an attempt to auto-satisfy each item (fuzzy-matching a free-text
        # requirement against generated sections would be more likely to
        # give false reassurance than real coverage).
        lines.append("## Report Requirements (per Statement of Work)")
        lines.append("The authorizing SOW specifies this deliverable must include:")
        lines.extend(f"- [ ] {r}" for r in report_requirements)
        lines.append("")

    if warnings:
        lines.append("## Warnings")
        lines.extend(f"- {w}" for w in warnings)
        lines.append("")

    lines.append("## Summary")
    lines.append(summary or "No summary.")
    lines.append("")

    if findings:
        # Free — the finding schema already carries this, and it's near-
        # universally expected in a professional pentest deliverable
        # regardless of what the SOW's own wording asks for.
        tools = sorted({f["source_tool"] for f in findings if f.get("source_tool")})
        if tools:
            lines.append("## Methodology")
            lines.append("Tools used during this engagement:")
            lines.extend(f"- {t}" for t in tools)
            lines.append("")

    lines.append("## Findings")
    if not findings:
        lines.append("No findings.")
    else:
        for f in sorted(findings, key=_severity_rank):
            loc = ""
            if f.get("file_path"):
                loc = f" ({f['file_path']}:{f['line']})" if f.get("line") else f" ({f['file_path']})"
            tool_part = f"[{f['source_tool']}] " if f.get("source_tool") else ""
            severity = str(f.get("severity", "")).upper()
            lines.append(f"### {tool_part}[{severity}] {f['title']}{loc}")
            lines.append("")
            lines.append(f.get("description", ""))
            lines.append("")

    return "\n".join(lines)


def write_report(path: str, content: str) -> Path:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(content, encoding="utf-8")
    return out
