# Roadmap

## Phase 0 — Documentation (current)

This doc set. No code yet.

## Phase 1 — Usable loop

Agent Core + Memory + CLI, working end to end against real (owned/lab)
targets and real local repos. Success bar: you reach for `security scan` /
`security analyze` / `security fix` over doing the equivalent by hand,
daily, yourself.

## Phase 2 — Tool Orchestrator

Full recon → active chain behind the scope gate. Success bar: a `security
scan` on a lab/authorized target produces findings you'd trust enough to
put in a real report.

## Phase 3 — Thin clients

VS Code extension, Chrome extension. Both call the same Agent Core the CLI
already uses — no new agent logic introduced here.

## Phase 4 — Expand the agent roster (only after Phase 1–3 are daily-used)

Roughly in this order, each gated on the previous being genuinely useful,
not just built:

1. Report Agent (there needs to be finding volume in Memory first)
2. Bug Hunting Agent (composes Pentest + Browser against a defined scope)
3. Cloud Agent / IAM Agent (your existing Azure/IAM background makes these
   high-leverage once the core loop is trusted)
4. SOC Agent
5. OSINT Agent (strictly passive)
6. Reverse Engineering / Malware Agent (sandboxed, no host network access)

## Phase 5 — Distribution surfaces (only if this becomes a product)

Desktop app (Tauri), Firefox extension, voice commands, team
collaboration/shared Memory. None of these matter until Phase 1–4 are solid
for a single user.

## Open decisions to revisit

- **Licensing model** — currently proprietary/private (see LICENSE). Revisit
  open-core vs. fully-closed once there's something worth commercializing.
- **"Leviathan" naming** — common name in the security tooling space; do a
  trademark/naming search before any public release (docs/REVIEW.md point 7).
- **Team/multi-user Memory** — out of scope until Phase 5; current design
  assumes single-user local Memory.
