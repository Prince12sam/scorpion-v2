"""Unit tests for SOW parsing (api/sow.py). Mocks the LLM call — the
contract being tested is "does parse_sow correctly consume whatever JSON
the model returns," not any specific model's phrasing. That judgment call
itself was verified separately, for real, against a local Ollama model:
a SOW explicitly authorizing exploitation parsed to
exploitation_authorized=True with a correct citation, and a vague
"penetration test" SOW correctly parsed to False.
"""

import pytest

import api.sow as sow_module
from api.sow import SowParseError, parse_sow


def test_parse_sow_returns_the_models_json(monkeypatch):
    monkeypatch.setattr(
        sow_module,
        "complete",
        lambda *a, **k: '{"targets": ["example.com"], "exploitation_authorized": true, "reasoning": "explicit"}',
    )
    result = parse_sow("some SOW text")
    assert result == {"targets": ["example.com"], "exploitation_authorized": True, "reasoning": "explicit"}


def test_parse_sow_strips_markdown_fences(monkeypatch):
    monkeypatch.setattr(
        sow_module,
        "complete",
        lambda *a, **k: '```json\n{"targets": ["a.com"], "exploitation_authorized": false, "reasoning": "n/a"}\n```',
    )
    result = parse_sow("some SOW text")
    assert result["targets"] == ["a.com"]
    assert result["exploitation_authorized"] is False


def test_parse_sow_raises_on_malformed_json(monkeypatch):
    monkeypatch.setattr(sow_module, "complete", lambda *a, **k: "not json at all")
    with pytest.raises(SowParseError):
        parse_sow("some SOW text")


def test_parse_sow_raises_on_missing_required_fields(monkeypatch):
    monkeypatch.setattr(sow_module, "complete", lambda *a, **k: '{"targets": ["a.com"]}')
    with pytest.raises(SowParseError):
        parse_sow("some SOW text")


def test_parse_sow_returns_report_requirements_when_present(monkeypatch):
    monkeypatch.setattr(
        sow_module,
        "complete",
        lambda *a, **k: (
            '{"targets": ["example.com"], "exploitation_authorized": false, "reasoning": "n/a", '
            '"report_requirements": ["executive summary", "CVSS score per finding"]}'
        ),
    )
    result = parse_sow("some SOW text")
    assert result["report_requirements"] == ["executive summary", "CVSS score per finding"]


def test_parse_sow_omits_report_requirements_without_raising(monkeypatch):
    # report_requirements isn't in the required-fields check — a SOW with
    # no deliverable/reporting clause, or an older model response that
    # simply doesn't include the key, shouldn't fail the whole parse.
    monkeypatch.setattr(
        sow_module,
        "complete",
        lambda *a, **k: '{"targets": ["example.com"], "exploitation_authorized": false, "reasoning": "n/a"}',
    )
    result = parse_sow("some SOW text")
    assert result.get("report_requirements") is None


def test_parse_sow_raises_when_llm_unavailable(monkeypatch):
    from api.llm_router import LLMUnavailable

    def _raise(*a, **k):
        raise LLMUnavailable("no provider configured")

    monkeypatch.setattr(sow_module, "complete", _raise)
    with pytest.raises(SowParseError):
        parse_sow("some SOW text")
