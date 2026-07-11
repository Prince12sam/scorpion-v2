# Agent Roster

A Master Agent routes each request to one or more specialists. Each
specialist has a narrow tool allowlist and system prompt — it should not
know how to do another specialist's job.

## MVP agents (built now)

### Coding Agent
- **Tools:** filesystem read/write, semgrep, test runner, git.
- **Flow:** read code → find issues → explain → patch → run tests → commit.
  PR creation is an explicit opt-in per repo, never a default action
  (docs/REVIEW.md point 6).
- **Backs:** `security fix`, `security analyze`, VS Code extension.

### Pentest Agent
- **Tools:** the Tool Orchestrator's active chain (nmap, httpx, subfinder,
  katana, nuclei, ffuf, dalfox, sqlmap) — every call gated by scope
  verification.
- **Flow:** recon → surface mapping → targeted active testing → findings to
  Memory.
- **Backs:** `security scan`.

### Browser Agent
- **Tools:** passive page inspection (headers, CSP, cookies, storage, CORS,
  robots.txt/sitemap, JS parsing for keys/secrets, fingerprinting, WAF
  detection) by default; active checks (GraphQL introspection, endpoint
  fuzzing) only behind the scope gate + explicit user action.
- **Flow:** on page load, run passive checks, surface a summary, offer next
  active step as an explicit choice (not an implicit auto-run).
- **Backs:** browser extension.

## Deferred agents (post-MVP, see docs/ROADMAP.md)

- **Bug Hunting Agent** — orchestrates Pentest + Browser agents against a
  defined bug-bounty scope with a checkpoint before any active submission.
- **Reverse Engineering Agent** — static/dynamic binary analysis, sandboxed.
- **SOC Agent** — log/alert triage, correlation, playbook suggestions.
- **Cloud Agent** — AWS/Azure/GCP misconfiguration review, IaC (Terraform/
  Kubernetes) review.
- **IAM Agent** — Active Directory and identity/access assessments.
- **OSINT Agent** — public-source enumeration, kept strictly passive.
- **Malware Agent** — sample triage in an isolated sandbox only, never given
  network access to the host machine.
- **Report Agent** — turns Memory findings into a reproducible report with
  evidence links; only worth building once there's enough real finding
  volume flowing through Memory to report on.

## Master Agent

Routing only — given a request, decides which specialist(s) handle it and in
what order, then hands off to the Agent Core's Planner. It does not itself
call tools.
