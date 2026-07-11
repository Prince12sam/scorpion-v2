# Architecture

```
                      ┌───────────────────────┐
                      │   Browser Extension    │  (Phase 3, thin client)
                      └──────────┬─────────────┘
                                 │
                      ┌───────────────────────┐
                      │  VS Code Extension     │  (Phase 3, thin client)
                      └──────────┬─────────────┘
                                 │
                      ┌───────────────────────┐
                      │        CLI             │  (Phase 1)
                      └──────────┬─────────────┘
                                 │  HTTP / local API
┌────────────────────────────────────────────────────────────┐
│                      Agent Core (FastAPI)                    │
├────────────────────────────────────────────────────────────┤
│  Planner         → task graph from a request                │
│  Context Manager → assembles per-step context, budget-aware  │
│  Tool Router      → maps step → tool call, enforces scope gate│
│  LLM Router       → picks model per step, cloud/local fallback│
└──────────┬─────────────────────────────────┬─────────────────┘
           │                                 │
┌──────────▼───────────┐         ┌───────────▼─────────────┐
│   Tool Orchestrator    │         │        Memory            │
│  (Phase 2)             │         │  (Phase 1)                │
│  nmap · httpx · katana │         │  Postgres + pgvector      │
│  nuclei · ffuf · sqlmap│         │  projects/targets/findings│
│  semgrep · subfinder   │         │  notes, credential refs   │
└────────────────────────┘         └───────────────────────────┘
```

## Component responsibilities

**Planner.** Turns a request ("scan farlabs.ai", "fix app/") into an ordered
task graph. Does not itself call tools — hands steps to the Tool Router one
at a time so each call can be gated and logged independently.

**Context Manager.** Pulls the minimum needed context per step from Memory
(prior findings on this target, relevant code, project notes) instead of
stuffing the whole project/target history into every call.

**Tool Router.** The only component allowed to invoke a tool. Every
invocation passes through the authorization gate
(docs/SECURITY_AND_AUTHORIZATION.md) before anything active runs, and every
result is normalized to one finding schema before it reaches Memory.

**LLM Router.** Chooses a model per step based on: task type (code edit vs.
recon summarization vs. fast chat), data sensitivity (does this step's
context contain a live secret? → local model only), and availability
(cloud call failed/rate-limited → fall back to local). Not a hardcoded
single-model dependency.

**Tool Orchestrator.** Coordinates the actual external tools behind one
interface, so the Agent Core never shells out directly and every tool's
output lands in the same shape in Memory.

**Memory.** Single Postgres + pgvector store. See docs/MVP.md #2 and
docs/REVIEW.md point 3 for why this replaced the original three-store design.

## Why agents are specialized, not one prompt

Each specialist (Coding, Pentest, Browser, SOC, Cloud, ...) gets a narrow
tool allowlist and a focused system prompt instead of one prompt trying to
know nmap flags, IAM policy syntax, and React patterns simultaneously. The
Master Agent's job is only routing a request to the right specialist(s) —
see docs/AGENTS.md.
