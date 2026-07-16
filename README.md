# Scorpion v2

Scorpion is a local-first AI security platform: a Coding Agent (`analyze`/`fix`,
security-focused static review + LLM-assisted patching) and a Pentest
Agent (`scan`, chaining httpx, subfinder, katana, nmap, nuclei, ffuf,
dalfox, sqlmap, and OWASP ZAP) behind one CLI, orchestrated by an LLM
router that works with either a cloud provider or a local model (Ollama).

`scan` doesn't just check the one host you give it — it enumerates
subdomains, probes which are actually live, and runs the full active-scan
chain against every live host it finds, not just the original target.

## Status

The Agent Core, Memory, CLI, and Tool Orchestrator are built and verified
end-to-end — including against real live targets, not just synthetic
fixtures, on both Windows and Linux. Start with
[docs/GETTING_STARTED.md](docs/GETTING_STARTED.md) to actually run it.

## Start here

| Doc | What it covers |
|---|---|
| [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md) | Setup and usage — start here to actually run Scorpion |
| [docs/WINDOWS.md](docs/WINDOWS.md) | What's different (and what actually went wrong and got fixed) on Windows |
| [docs/LINUX.md](docs/LINUX.md) | What's different on Linux — verified on Kali |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Agent core, tool router, LLM router, memory — how the pieces fit |

## Non-negotiables

1. **No active scan/exploit action fires against a target that isn't in an explicitly authorized, technically-verified scope.** A conversational "may I?" is not a gate — every active tool call passes through a scope check enforced in code.
2. **Secrets never leave the machine.** Anything found that looks like a credential, API key, or token is redacted before it's ever sent to a cloud LLM.
3. **Every LLM call is bounded by a real timeout**, enforced in code independent of whether the underlying provider honors its own timeout setting.
