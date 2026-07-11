# Leviathan

Leviathan is a local-first "AI Security OS": a multi-agent platform that fuses
an AI coding assistant (Claude Code / Copilot / Cursor-style workflows) with a
security testing toolchain (Burp Suite / Nuclei / Kali-style tooling) under
one orchestration layer, driven by an LLM router with local-model fallback.

The long-term vision covers coding, pentesting, bug hunting, reverse
engineering, SOC investigation, cloud/IAM assessment, OSINT, and automated
reporting — see [docs/VISION.md](docs/VISION.md).

**We are not building all of that at once.** Current work is scoped to a
6-component MVP. See [docs/MVP.md](docs/MVP.md) for what's actually being
built first and why.

## Status

Documentation / design phase. No code yet. This README and the `docs/`
directory are the source of truth for scope until implementation starts.

## Start here

| Doc | What it covers |
|---|---|
| [docs/MVP.md](docs/MVP.md) | The 6 components being built first, in order, with acceptance criteria |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Agent core, tool router, LLM router, memory — how the pieces fit |
| [docs/AGENTS.md](docs/AGENTS.md) | The specialized agent roster (Coding, Pentest, Browser, SOC, Cloud, ...) |
| [docs/TECH_STACK.md](docs/TECH_STACK.md) | Chosen stack per component, with what was deliberately cut from the original list and why |
| [docs/SECURITY_AND_AUTHORIZATION.md](docs/SECURITY_AND_AUTHORIZATION.md) | **Read before writing any active-scanning code.** Scope gating, secrets handling, data egress rules |
| [docs/ROADMAP.md](docs/ROADMAP.md) | Phased plan from MVP to the full vision, licensing status |
| [docs/VISION.md](docs/VISION.md) | The full long-term picture (all agents, all future features) |
| [docs/REVIEW.md](docs/REVIEW.md) | Critical review of the original concept: what's sound, what's risky, what changed and why |

## Non-negotiables

1. **No active scan/exploit action fires against a target that isn't in an explicitly authorized, technically-verified scope.** Conversational "may I?" is not a gate — see docs/SECURITY_AND_AUTHORIZATION.md.
2. **Secrets never leave the machine.** Anything the Browser Agent finds that looks like a credential, API key, or token is redacted before it's ever sent to a cloud LLM.
3. **MVP before vision.** New agents/features don't get built until the 6 MVP components are stable and something is actually using them daily.
