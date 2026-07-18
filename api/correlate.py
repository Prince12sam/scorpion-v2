"""Cross-tool finding correlation.

A real scan produces overlapping noise: nuclei, zap-full-scan, and dalfox
can all independently flag the same underlying issue on the same URL. This
merges those into one entry instead of listing them as unrelated findings,
so a report reflects distinct issues, not distinct tool invocations.

Heuristic, not certain — a finding that can't be confidently matched (no
extractable URL, or no recognized category) passes through unchanged
rather than being guessed into the wrong group. Exact byte-identical
duplicates (the same tool reporting the same title+description twice,
e.g. via enumeration touching the same host from two angles) are always
collapsed, since that's unambiguous.
"""

import re

_URL_RE = re.compile(r"https?://[^\s)'\"<>]+")

# Order matters only in that the first matching category wins — kept
# short and specific rather than broad, so a finding with no real match
# passes through instead of getting miscategorized.
_CATEGORIES: list[tuple[str, tuple[str, ...]]] = [
    ("XSS", ("xss", "cross-site scripting")),
    ("SQL Injection", ("sql injection", "sqli")),
    (
        "Missing/Misconfigured Security Header",
        ("header missing", "header not set", "header is missing", "header was not set", "header-missing"),
    ),
    ("Version/Banner Disclosure", ("banner", "version information", "version disclosure", "leaking version")),
    ("Confirmed Impact", ("confirmed impact",)),
]

_SEVERITY_RANK = {"critical": 0, "high": 1, "error": 1, "medium": 2, "warning": 2, "low": 3, "info": 4}


def _extract_url(finding: dict) -> str | None:
    text = f"{finding.get('title', '')} {finding.get('description', '')}"
    match = _URL_RE.search(text)
    return match.group(0).rstrip(".,)") if match else None


def _categorize(finding: dict) -> str | None:
    text = f"{finding.get('title', '')} {finding.get('description', '')}".lower()
    for name, keywords in _CATEGORIES:
        if any(keyword in text for keyword in keywords):
            return name
    return None


def correlate_findings(findings: list[dict]) -> list[dict]:
    """Exact duplicates collapsed; findings sharing an extracted URL and
    category merged into one entry with a `correlated_tools` list.
    Everything else — including anything with no URL/category match, like
    semgrep's file-path findings — passes through unchanged.
    """
    seen_exact: set[tuple] = set()
    groupable: dict[tuple[str, str], list[dict]] = {}
    passthrough: list[dict] = []

    for f in findings:
        key = (f.get("source_tool"), f.get("title"), f.get("description"))
        if key in seen_exact:
            continue  # byte-identical — genuinely the same line, not "related"
        seen_exact.add(key)

        url = _extract_url(f)
        category = _categorize(f)
        if url and category:
            groupable.setdefault((url, category), []).append(f)
        else:
            passthrough.append(f)

    merged: list[dict] = []
    for (url, category), items in groupable.items():
        if len(items) == 1:
            passthrough.append(items[0])
            continue
        tools = sorted({i["source_tool"] for i in items})
        best = min(items, key=lambda i: _SEVERITY_RANK.get(str(i.get("severity", "")).lower(), 99))
        merged.append(
            {
                "source_tool": "+".join(tools),
                "severity": best["severity"],
                "title": f"[{category}] {url}",
                "description": (
                    f"Confirmed by {len(tools)} tool(s): {', '.join(tools)}. "
                    + " | ".join(f"{i['source_tool']}: {i['title']}" for i in items)
                ),
                "file_path": None,
                "line": None,
                "correlated_tools": tools,
            }
        )

    return passthrough + merged
