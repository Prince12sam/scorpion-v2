# Design Review: Original Leviathan Concept

This is a critical pass over the initial vision doc — what's sound, what's
risky, and what changed in the docs that followed from it. Written before any
code exists, so it can still change cheaply.

## What's sound

- **Multi-agent-over-one-agent** is the right call. A master agent routing to
  narrow specialists (Coding, Pentest, Browser, SOC...) keeps prompts small
  and lets each agent carry a tight, reliable tool set instead of one
  god-prompt trying to do everything.
- **LLM router with fallback** (cloud + local) is a real need, not
  over-engineering — pentest/recon workloads are bursty and you'll want to
  fall back to a local model when rate-limited, offline, or handling
  sensitive data (see the egress point below).
- **CLI-first, tool-orchestrator-in-the-middle** design (`security scan
  target` deciding the nmap → httpx → nuclei → ffuf chain) is the actual
  differentiator versus just scripting these tools together — worth
  protecting as the MVP's core value, not diluting it across six surfaces at
  once.
- **MVP scope-down to 6 components** was already the right instinct in the
  original doc. We kept it and cut two more (see docs/TECH_STACK.md).

## What's risky and was changed

1. **"Then asks: do you want me to enumerate the GraphQL schema?" is not an
   authorization gate.** A conversational confirmation is a UX nicety, not a
   safety control — it does nothing to stop the agent (or a user, or a
   prompt-injected page) from pointing active tooling at a target nobody
   authorized. The MVP now requires a technical, file/DNS-verified scope
   record before ANY active module (nmap SYN scans, sqlmap, ffuf, nuclei
   active templates, Playwright login-and-click automation) will run against
   a host. Passive/read-only recon (headers, robots.txt, public JS parsing)
   is not gated the same way. Full design in
   docs/SECURITY_AND_AUTHORIZATION.md.

2. **Cloud LLM exposure of found secrets.** The Browser Agent's job
   description includes finding AWS/Azure/Stripe/Firebase keys and JWTs. The
   original doc then routes everything through "LLM Router → Claude / GPT /
   Gemini / ...". Sending live credentials to a third-party API to have them
   "explained" is a real data-exfiltration risk and a liability for a
   commercial product. Fix: a redaction/classification pass runs locally
   (regex + local model) before anything touches a cloud LLM; secrets are
   stored encrypted-at-rest in a local vault, never embedded into pgvector.

3. **Memory stack was three overlapping systems** (Postgres+pgvector, SQLite,
   ChromaDB) with no stated reason for the overlap. Consolidated to Postgres
   + pgvector for everything (structured + vector), with SQLite only as the
   offline/embedded fallback when Postgres isn't running. Chroma dropped —
   it's redundant with pgvector once you already run Postgres.

4. **Six MVP components was still too wide for a first slice.** Shipping a
   CLI, a VS Code extension, a browser extension, a tool orchestrator, and a
   memory layer simultaneously means nothing is finished for a long time.
   docs/MVP.md sequences them: agent core + CLI + orchestrator + memory ship
   first as a usable loop end-to-end; the VS Code and browser extensions are
   thin clients added once that loop is solid.

5. **Desktop app (Tauri) and dual browser extensions (Chrome + Firefox)** in
   the original tech stack are distribution surfaces, not core value, and
   were cut from the MVP tech stack entirely. Revisit once there's a working
   CLI + single Chrome extension people actually use daily.

6. **Autonomous PR creation** ("Coding Agent... creates PR") should require
   an explicit opt-in per repo, not be a default action, given it pushes to
   shared state. Aligns with this environment's own confirm-before-side-effect
   norms.

7. **Name collision check**: "Leviathan" is a common name in the security
   tooling space (there have been unrelated open-source projects using it
   over the years). Not a blocker for a private/internal tool, but worth a
   trademark/naming search before any public or commercial release — tracked
   in docs/ROADMAP.md.

## Net effect

Nothing in the original vision was wrong at the concept level — it's a
coherent architecture. The changes above are about sequencing (do less,
first) and about closing two gaps (authorization gating, secrets egress)
that matter a lot more for a tool that runs active security tooling than
they would for a plain coding assistant.
