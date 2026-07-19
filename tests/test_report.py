"""Pure-logic tests for cli/report.py's Markdown rendering — no LLM/Docker
involved, just checking the generated text structure."""

from cli.report import render_markdown


def test_render_markdown_omits_sow_section_when_no_requirements():
    content = render_markdown("Title", "example.com", [], "summary")
    assert "Report Requirements" not in content


def test_render_markdown_includes_sow_requirements_as_a_checklist():
    content = render_markdown(
        "Title",
        "example.com",
        [],
        "summary",
        report_requirements=["executive summary", "CVSS score per finding"],
    )
    assert "## Report Requirements (per Statement of Work)" in content
    assert "- [ ] executive summary" in content
    assert "- [ ] CVSS score per finding" in content


def test_render_markdown_includes_methodology_section_when_findings_exist():
    findings = [
        {"source_tool": "nuclei", "severity": "high", "title": "x", "description": "d"},
        {"source_tool": "nikto", "severity": "info", "title": "y", "description": "d"},
        {"source_tool": "nuclei", "severity": "low", "title": "z", "description": "d"},
    ]
    content = render_markdown("Title", "example.com", findings, "summary")
    assert "## Methodology" in content
    assert "- nikto" in content
    assert "- nuclei" in content


def test_render_markdown_omits_methodology_section_when_no_findings():
    content = render_markdown("Title", "example.com", [], "summary")
    assert "## Methodology" not in content
