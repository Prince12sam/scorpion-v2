"""Unit-level checks that each Phase 2 tool actually executes and its
output parses — bypassing the scope gate (that's covered separately in
test_scan.py) since these just prove the tool_router <-> container
integration works, matched against a local, hermetic HTTP server."""

import functools
import http.server
import tempfile
import threading
from pathlib import Path

from api.config import settings
from api.tool_router import (
    run_dalfox,
    run_ffuf,
    run_katana,
    run_nuclei,
    run_sqlmap,
    run_subfinder,
    run_zap_baseline,
    run_zap_full_scan,
)

TARGET_HOST = settings.container_host_alias


class _TestHTTPServer(http.server.ThreadingHTTPServer):
    # socketserver's default listen backlog is 5 — too small for ffuf's
    # default 40 concurrent connections arriving in a burst, some still got
    # refused even with threading. This is purely a test-fixture limit, not
    # a real product concern (proven separately against a real production
    # site) — a real server's own backlog is the target's problem, not ours.
    request_queue_size = 128


def _start_http_server(port: int) -> tuple[http.server.ThreadingHTTPServer, tempfile.TemporaryDirectory]:
    tmpdir = tempfile.TemporaryDirectory()
    (Path(tmpdir.name) / "robots.txt").write_text("User-agent: *\n")
    (Path(tmpdir.name) / "index.html").write_text("<html>hi</html>")

    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=tmpdir.name)
    httpd = _TestHTTPServer(("0.0.0.0", port), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, tmpdir


def test_subfinder_finds_real_subdomains():
    # example.com is IANA's reserved documentation domain (RFC 2606) —
    # subfinder only queries public passive sources (crt.sh etc.), it never
    # contacts example.com's own servers, so this is safe without a scope
    # verification.
    findings = run_subfinder("example.com")
    assert len(findings) > 0
    assert all(f["source_tool"] == "subfinder" for f in findings)


def test_katana_crawls_local_server():
    port = 8791
    httpd, tmpdir = _start_http_server(port)
    try:
        findings = run_katana(f"http://{TARGET_HOST}:{port}")
    finally:
        httpd.shutdown()
        tmpdir.cleanup()
    assert any(f["source_tool"] == "katana" for f in findings)


def test_ffuf_finds_a_known_path():
    port = 8792
    httpd, tmpdir = _start_http_server(port)
    try:
        findings = run_ffuf(f"http://{TARGET_HOST}:{port}")
    finally:
        httpd.shutdown()
        tmpdir.cleanup()
    assert any("robots.txt" in f["title"] for f in findings)


def test_nuclei_runs_a_real_scan_cleanly():
    port = 8793
    httpd, tmpdir = _start_http_server(port)
    try:
        findings = run_nuclei(f"http://{TARGET_HOST}:{port}")
    finally:
        httpd.shutdown()
        tmpdir.cleanup()
    # A static file server should trip zero templates — this asserts the
    # tool ran and parsed cleanly, not that it found something.
    assert findings == []


def test_dalfox_runs_a_real_scan_cleanly():
    port = 8794
    httpd, tmpdir = _start_http_server(port)
    try:
        findings = run_dalfox(f"http://{TARGET_HOST}:{port}")
    finally:
        httpd.shutdown()
        tmpdir.cleanup()
    assert findings == []


def test_sqlmap_runs_a_real_scan_cleanly():
    port = 8795
    httpd, tmpdir = _start_http_server(port)
    try:
        findings = run_sqlmap(f"http://{TARGET_HOST}:{port}/?id=1")
    finally:
        httpd.shutdown()
        tmpdir.cleanup()
    assert findings == []


def test_zap_baseline_runs_a_real_scan_cleanly():
    port = 8796
    httpd, tmpdir = _start_http_server(port)
    try:
        findings = run_zap_baseline(f"http://{TARGET_HOST}:{port}")
    finally:
        httpd.shutdown()
        tmpdir.cleanup()
    # Unlike nuclei/dalfox/sqlmap (which hunt exploitable vulnerabilities a
    # bare static file server genuinely has none of), ZAP's passive scanner
    # also flags general hygiene issues — e.g. Python's SimpleHTTPRequestHandler
    # sends no Content-Security-Policy header, which is a real, correct
    # finding. This asserts the report round-trips through the mounted
    # volume and parses into well-formed findings, not that it's empty.
    assert len(findings) > 0
    assert all(f["source_tool"] == "zap-baseline" for f in findings)
    assert all(f["severity"] in ("info", "low", "medium", "high") for f in findings)


def test_zap_full_scan_runs_a_real_scan_cleanly():
    port = 8797
    httpd, tmpdir = _start_http_server(port)
    try:
        findings = run_zap_full_scan(f"http://{TARGET_HOST}:{port}")
    finally:
        httpd.shutdown()
        tmpdir.cleanup()
    assert len(findings) > 0
    assert all(f["source_tool"] == "zap-full-scan" for f in findings)
    assert all(f["severity"] in ("info", "low", "medium", "high") for f in findings)
