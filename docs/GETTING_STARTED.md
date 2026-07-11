# Getting Started (Phase 1)

Phase 1 is Agent Core + Memory + CLI (`analyze` / `fix`) — see docs/MVP.md.
`es scan` is a stub; it depends on the Phase 2 Tool Orchestrator.

## Prerequisites

- Python 3.11+
- Docker Desktop (running) — used for Postgres+pgvector and for running
  semgrep in a container (semgrep has no native Windows build)

## Setup

```
python -m venv .venv
.venv\Scripts\activate          # Windows
pip install -r requirements.txt

cp .env.example .env             # then fill in ES_CODING_MODELS + a provider key
                                  # (optional — analyze/fix work without one,
                                  # just without LLM summaries/patches)

cd docker
docker compose up -d             # starts Postgres+pgvector on localhost:55432
cd ..
```

## Run the Agent Core

```
uvicorn api.main:app --host 127.0.0.1 --port 8731
```

On startup it creates the `vector` extension and all tables if they don't
exist yet (fine for MVP; a real migration tool comes once the schema
stabilizes — see docs/ROADMAP.md).

## Use the CLI

```
python -m cli.main analyze path/to/code
python -m cli.main fix path/to/repo              # proposes a patch, doesn't touch disk
python -m cli.main fix path/to/repo --apply       # writes the patch, runs pytest
python -m cli.main fix path/to/repo --apply --commit   # + commits if tests pass
```

## Without an LLM key configured

`analyze` still runs semgrep and returns raw findings; the summary field
explains that no LLM is configured instead of a real summary. `fix` requires
an LLM (semgrep alone doesn't write patches) and will return a clear error
if none is configured.

## Notes

- `fix --apply` assumes `path` is a git repository (uses `git apply` / `git
  commit`). Commit is opt-in and only happens if `pytest` passes after the
  patch is applied — see docs/REVIEW.md point 6.
- Findings are persisted to Memory (Postgres) keyed by project name. If
  Postgres isn't reachable, `analyze`/`fix` still work — you just won't get
  cross-session recall of past findings.
