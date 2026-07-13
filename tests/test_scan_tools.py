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
from api.tool_router import run_dalfox, run_ffuf, run_katana, run_nuclei, run_sqlmap, run_subfinder

TARGET_HOST = settings.container_host_alias


def _start_http_server(port: int) -> tuple[http.server.ThreadingHTTPServer, tempfile.TemporaryDirectory]:
    tmpdir = tempfile.TemporaryDirectory()
    (Path(tmpdir.name) / "robots.txt").write_text("User-agent: *\n")
    (Path(tmpdir.name) / "index.html").write_text("<html>hi</html>")

    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=tmpdir.name)
    # Plain (single-threaded) HTTPServer/TCPServer handles one connection at
    # a time — found the hard way that ffuf's default 40 concurrent
    # connections mostly get refused/dropped against it, making results
    # look randomly incomplete even though the tool itself is working fine
    # (proven separately against a real production site). Threaded server
    # actually handles concurrent tools correctly.
    httpd = http.server.ThreadingHTTPServer(("0.0.0.0", port), handler)
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
