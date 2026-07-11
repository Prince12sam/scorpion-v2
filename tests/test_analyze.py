from pathlib import Path

from fastapi.testclient import TestClient

from api.main import app

FIXTURE = Path(__file__).parent / "fixtures" / "vulnerable_app"


def test_analyze_finds_known_issues():
    client = TestClient(app)
    response = client.post("/v1/analyze", json={"path": str(FIXTURE)})
    assert response.status_code == 200

    body = response.json()
    findings = body["findings"]
    assert len(findings) >= 2

    rule_ids = " ".join(f["title"] for f in findings)
    assert "eval" in rule_ids.lower() or "subprocess" in rule_ids.lower()
