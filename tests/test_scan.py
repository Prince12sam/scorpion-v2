import http.server
import socketserver
import threading
import uuid

from fastapi.testclient import TestClient

from api.config import settings
from api.main import app
from api.tool_router import run_httpx, run_nmap


def _start_http_server(port: int) -> socketserver.TCPServer:
    httpd = socketserver.TCPServer(("0.0.0.0", port), http.server.SimpleHTTPRequestHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def _unique_test_domain() -> str:
    """A fresh, guaranteed-never-resolving domain per call — never a fixed
    name. Two reasons: (1) a hardcoded name like "example.com" is a real,
    live, resolvable domain that anyone (a person testing the CLI, another
    test run) can independently touch at the same time, and Memory is
    shared state, so two unrelated actors both using it collide silently;
    (2) even with the scope gate working correctly, a fixed test domain
    also means the SAME target row gets reused (and potentially verified)
    across runs, so a later run's assumptions about its state silently
    depend on an earlier run's side effects. `.invalid` is reserved by
    RFC 2606 and is guaranteed to never resolve, so even a scope-gate bug
    here can't cause a real request to reach a real host."""
    return f"es-test-{uuid.uuid4().hex[:12]}.invalid"


def test_scan_denies_active_action_on_unverified_third_party_target():
    """The scope gate must block active tools against a target nobody
    verified — this must hold even if a caller asks for it directly."""
    client = TestClient(app)
    response = client.post("/v1/scan", json={"target": _unique_test_domain()})
    assert response.status_code == 200

    body = response.json()
    assert body["findings"] == []
    assert any("skipped" in w for w in body["warnings"])


def test_self_attestation_updates_scope_without_touching_a_real_host():
    """Self-attestation is the weakest verification method by design — this
    checks it correctly updates the Target row's authorization state. It
    deliberately does NOT follow up with a real /v1/scan call: doing that
    against any real, resolvable domain would mean actually firing nmap,
    nuclei, dalfox, and sqlmap at a third party with no real authorization
    behind it, which is exactly what this gate exists to prevent.
    """
    client = TestClient(app)
    target = _unique_test_domain()

    before = client.post("/v1/targets/status", json={"target": target}).json()
    assert before["status"] == "unverified"

    attest = client.post(
        "/v1/targets/self-attest", json={"target": target, "statement": "test: I own this"}
    ).json()
    assert attest["status"] == "verified"
    assert "self-attested" in attest["verification_method"]

    after = client.post("/v1/targets/status", json={"target": target}).json()
    assert after["status"] == "verified"


def test_local_target_auto_verified_and_scan_wires_through():
    """localhost is auto-verified (docs/SECURITY_AND_AUTHORIZATION.md #4) —
    both pipeline stages should actually run, not be skipped."""
    client = TestClient(app)
    response = client.post("/v1/scan", json={"target": "localhost"})
    assert response.status_code == 200

    body = response.json()
    assert not any("skipped" in w for w in body["warnings"])


def test_nmap_detects_a_specific_open_port_on_the_host():
    port = 8765
    httpd = _start_http_server(port)
    try:
        findings = run_nmap(settings.container_host_alias, ports=str(port))
    finally:
        httpd.shutdown()

    assert any(f"{port}" in f["title"] for f in findings)


def test_httpx_detects_the_same_service():
    port = 8766
    httpd = _start_http_server(port)
    try:
        findings = run_httpx(f"{settings.container_host_alias}:{port}")
    finally:
        httpd.shutdown()

    assert len(findings) >= 1
    assert findings[0]["source_tool"] == "httpx"
