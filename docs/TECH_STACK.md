# Tech Stack

## MVP

| Layer | Choice | Notes |
|---|---|---|
| Agent runtime | Python, FastAPI, LangGraph | Agent Core service |
| LLM access | LiteLLM (router) + Ollama (local runtime) | one interface over cloud + local models |
| Background jobs | Celery + Redis | active-tool jobs (scans can run minutes), not request/response |
| CLI | Typer + Rich | `security scan/analyze/fix` |
| VS Code extension | TypeScript, VS Code Extension API | thin client, Phase 3 |
| Browser extension | Chrome only (Manifest V3) | thin client, Phase 3; Firefox deferred |
| Database | PostgreSQL + pgvector | structured data + embeddings, one store |
| Offline fallback | SQLite | only when Postgres isn't running locally |
| Browser automation | Playwright | authenticated flows, deferred past MVP (docs/ROADMAP.md) |
| Security tools | nmap, httpx, subfinder, katana, nuclei, ffuf, dalfox, sqlmap, semgrep | run as sandboxed subprocesses/containers via the Tool Orchestrator |

## Local model roles (when the LLM Router picks local)

| Role | Model family |
|---|---|
| Coding | Qwen Coder |
| Reasoning | DeepSeek R1 |
| Fast chat | Llama 3.x |
| Vision | Qwen Vision |

Exact model versions aren't pinned here — the LLM Router should treat these
as swappable roles, not hardcoded model names, since local model quality
shifts fast.

## Cut from the original list, and why

| Cut | Reason |
|---|---|
| ChromaDB | Redundant with pgvector once Postgres is already required (docs/REVIEW.md point 3). |
| SQLite as a parallel primary store | Kept only as an offline fallback, not a third parallel store. |
| Tauri desktop app | Distribution surface, not core value; revisit once CLI + one browser extension are used daily (docs/REVIEW.md point 5). |
| Firefox extension | Ship one browser well before maintaining two extension codebases. |
| Textual (TUI) | Rich is enough for MVP CLI output; a full TUI is extra surface with no MVP requirement driving it. |

## Model providers behind the LLM Router

Claude, GPT, Gemini, Qwen, DeepSeek, Llama, Mistral — reachable via
LiteLLM/Ollama/vLLM as originally scoped. No provider is hardcoded into the
Agent Core; adding one is a router config change, not a code change to every
agent.
