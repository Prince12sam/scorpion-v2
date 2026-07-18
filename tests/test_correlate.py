"""Unit tests for cross-tool finding correlation, using finding shapes
actually observed from real tool runs earlier this session (ZAP header
alerts, sqlmap, dalfox, semgrep) rather than invented data."""

from api.correlate import correlate_findings


def _zap_header_finding(source_tool: str, url: str, header: str) -> dict:
    return {
        "source_tool": source_tool,
        "severity": "low",
        "title": f"{header} Header Missing",
        "description": f"<p>The {header} header was not set.</p> (1 instance(s), e.g. {url})",
        "file_path": None,
        "line": None,
    }


def test_same_url_same_category_findings_merge_across_tools():
    findings = [
        _zap_header_finding("zap-baseline", "http://example.com:8800/products/1", "X-Content-Type-Options"),
        _zap_header_finding("zap-full-scan", "http://example.com:8800/products/1", "Content-Security-Policy"),
    ]
    result = correlate_findings(findings)
    assert len(result) == 1
    assert set(result[0]["correlated_tools"]) == {"zap-baseline", "zap-full-scan"}
    assert "Missing/Misconfigured Security Header" in result[0]["title"]


def test_different_urls_do_not_merge():
    findings = [
        _zap_header_finding("zap-baseline", "http://example.com:8800/a", "X-Content-Type-Options"),
        _zap_header_finding("zap-baseline", "http://example.com:8800/b", "X-Content-Type-Options"),
    ]
    result = correlate_findings(findings)
    assert len(result) == 2


def test_different_categories_on_same_url_do_not_merge():
    xss = {
        "source_tool": "dalfox",
        "severity": "high",
        "title": "XSS: param",
        "description": "reflected XSS @ http://example.com:8800/search",
        "file_path": None,
        "line": None,
    }
    sqli = {
        "source_tool": "sqlmap",
        "severity": "error",
        "title": "possible SQL injection @ http://example.com:8800/search",
        "description": "GET parameter 'id' is vulnerable.",
        "file_path": None,
        "line": None,
    }
    result = correlate_findings([xss, sqli])
    assert len(result) == 2


def test_exact_duplicate_findings_collapse():
    finding = {
        "source_tool": "subfinder",
        "severity": "info",
        "title": "subdomain: api.example.com",
        "description": "source: crtsh",
        "file_path": None,
        "line": None,
        "host": "api.example.com",
    }
    result = correlate_findings([finding, dict(finding)])
    assert len(result) == 1


def test_semgrep_findings_pass_through_unchanged():
    """No URL to extract — must never be forced into a group."""
    findings = [
        {
            "source_tool": "semgrep",
            "severity": "error",
            "title": "python.lang.security.audit.subprocess-shell-true",
            "description": "Found 'subprocess' function 'run' with 'shell=True'.",
            "file_path": "app.py",
            "line": 5,
        },
        {
            "source_tool": "semgrep",
            "severity": "warning",
            "title": "python.lang.security.audit.eval-detected",
            "description": "Detected the use of eval().",
            "file_path": "app.py",
            "line": 10,
        },
    ]
    result = correlate_findings(findings)
    assert result == findings


def test_single_finding_in_a_category_is_not_wrapped_as_a_group():
    findings = [_zap_header_finding("zap-baseline", "http://example.com:8800/x", "X-Content-Type-Options")]
    result = correlate_findings(findings)
    assert result == findings
    assert "correlated_tools" not in result[0]
