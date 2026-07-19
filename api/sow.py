"""SOW (Statement of Work) ingestion — the only path that can grant the
"exploitation" scope tier (api/scope.py). Self-attestation and file-token
verification intentionally cannot: exploitation (confirming a
vulnerability's impact, not just detecting it) needs a stronger, explicit,
written authorization, not a one-line chat confirmation.
"""

import json

from api.llm_router import LLMUnavailable, complete

_SOW_PARSE_PROMPT = """You are a strict scope-authorization parser for an authorized security testing tool. Read the Statement of Work (SOW) below and extract ONLY what it explicitly states — do not infer or assume permissions it doesn't clearly grant.

Respond with ONLY a JSON object, no markdown fences, no explanation:
{{
  "targets": ["list of in-scope hostnames/domains/IPs explicitly named"],
  "exploitation_authorized": true or false,
  "reasoning": "one sentence citing the specific SOW language behind this decision",
  "report_requirements": ["list of specific deliverable/report content requirements the SOW explicitly states, e.g. 'executive summary', 'CVSS score per finding', 'remediation timeline' — empty list if the SOW doesn't specify a report format"]
}}

exploitation_authorized must be true ONLY if the SOW explicitly permits going beyond passive detection to confirm a vulnerability's real impact (e.g. explicitly allows enumerating database contents, extracting a proof-of-concept sample, demonstrating unauthorized access). General language like "penetration testing" or "vulnerability scanning" alone is NOT enough — when in doubt, answer false.

report_requirements must list ONLY deliverable/report content requirements the SOW explicitly states (e.g. a "Deliverables" or "Reporting" clause) — do not invent typical pentest report sections it doesn't actually mention.

SOW:
{sow_text}
"""


class SowParseError(Exception):
    pass


def _strip_markdown_fences(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        lines = text.splitlines()[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines)
    return text.strip()


def parse_sow(sow_text: str) -> dict:
    """Returns {"targets": [...], "exploitation_authorized": bool, "reasoning": str}.

    Raises SowParseError if no LLM is configured or the model's response
    isn't well-formed — exploitation authorization never falls back to a
    permissive default on a parse failure, it just fails closed.
    """
    try:
        raw = complete([{"role": "user", "content": _SOW_PARSE_PROMPT.format(sow_text=sow_text)}], purpose="coding")
    except LLMUnavailable as exc:
        raise SowParseError(f"cannot parse a SOW without an LLM configured: {exc}") from exc

    cleaned = _strip_markdown_fences(raw)
    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        raise SowParseError(f"could not parse the SOW analysis as JSON: {raw[:500]}") from exc

    if "targets" not in data or "exploitation_authorized" not in data:
        raise SowParseError(f"SOW analysis missing required fields: {data}")

    return data
