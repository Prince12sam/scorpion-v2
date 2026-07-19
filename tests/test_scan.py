import http.server
import threading
import uuid
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
from sqlalchemy import select

from api.config import settings
from api.main import app
from api.scope import EXPLOITATION, get_or_create_target, has_authorization, verify_sow
from api.tool_router import run_httpx, run_nmap
from memory.db import SessionLocal
from memory.models import Target


def _start_http_server(port: int) -> http.server.ThreadingHTTPServer:
    # ThreadingHTTPServer, not a plain single-threaded HTTPServer/TCPServer —
    # see tests/test_scan_tools.py's _start_http_server for why (ffuf's
    # concurrent connections mostly got dropped against a single-threaded
    # one, making results look randomly incomplete).
    httpd = http.server.ThreadingHTTPServer(("0.0.0.0", port), http.server.SimpleHTTPRequestHandler)
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
    return f"scorpion-test-{uuid.uuid4().hex[:12]}.invalid"


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


def test_self_attestation_never_grants_exploitation():
    """The 'exploitation' tier (sqlmap confirming real impact, not just
    detecting it) must only ever come from a parsed SOW — self-attestation
    is a one-line chat-adjacent statement, nowhere near strong enough."""
    client = TestClient(app)
    target = _unique_test_domain()
    client.post("/v1/targets/self-attest", json={"target": target, "statement": "test: I own this"})

    session = SessionLocal()
    try:
        assert not has_authorization(session, target, EXPLOITATION)
    finally:
        session.close()


def test_verify_sow_grants_exploitation_only_when_parsed_result_says_so():
    session = SessionLocal()
    try:
        target_a = _unique_test_domain()
        verify_sow(
            session, target_a, "a real SOW", {"targets": [target_a], "exploitation_authorized": True, "reasoning": "x"}
        )
        assert has_authorization(session, target_a, EXPLOITATION)

        target_b = _unique_test_domain()
        verify_sow(
            session,
            target_b,
            "a vague SOW",
            {"targets": [target_b], "exploitation_authorized": False, "reasoning": "y"},
        )
        assert not has_authorization(session, target_b, EXPLOITATION)

        # passive-recon/active-scan are unaffected either way — verify_sow
        # doesn't downgrade the tiers self-attestation/file-token also grant.
        row_a = get_or_create_target(session, target_a)
        assert row_a.sow_text == "a real SOW"
    finally:
        session.close()


def test_verify_sow_persists_report_requirements():
    session = SessionLocal()
    try:
        target = _unique_test_domain()
        verify_sow(
            session,
            target,
            "a real SOW",
            {
                "targets": [target],
                "exploitation_authorized": False,
                "reasoning": "x",
                "report_requirements": ["executive summary", "CVSS score per finding"],
            },
        )
        row = get_or_create_target(session, target)
        assert row.report_requirements == ["executive summary", "CVSS score per finding"]

        # Older/degenerate parsed results without the field shouldn't crash
        # or leave a stale value from a prior verification on the row.
        target_b = _unique_test_domain()
        verify_sow(session, target_b, "a real SOW", {"targets": [target_b], "exploitation_authorized": False})
        row_b = get_or_create_target(session, target_b)
        assert row_b.report_requirements == []
    finally:
        session.close()


def test_expired_verification_reports_as_expired_not_verified():
    """Regression: found on Kali against a real target (afrimarkethub.store)
    — a self-attestation past its TTL still reported status="verified" from
    /v1/targets/status, so `scan --self-attest` saw "already verified",
    never re-submitted the attestation, and every pipeline stage then
    denied anyway (require_authorized does check expiry, just too late to
    help). The DB column itself never flips on its own when a TTL passes —
    callers that decide whether to re-verify *before* running the pipeline
    have to see "expired", not a stale "verified"."""
    client = TestClient(app)
    target = _unique_test_domain()

    client.post("/v1/targets/self-attest", json={"target": target, "statement": "test: I own this"})

    session = SessionLocal()
    try:
        row = session.scalar(select(Target).where(Target.identifier == target))
        row.expires_at = datetime.now(timezone.utc) - timedelta(days=1)
        session.commit()
    finally:
        session.close()

    status = client.post("/v1/targets/status", json={"target": target}).json()
    assert status["status"] == "expired"


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
