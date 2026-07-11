# Long-Term Vision

This is the full picture Leviathan is aimed at eventually. It is **not**
current scope — see docs/MVP.md for what's actually being built, and
docs/ROADMAP.md for sequencing. Kept here so later phases have a fixed
reference instead of relying on memory of the original pitch.

## One-line pitch

Combine Claude Code / GitHub Copilot / Cursor / OpenHands (AI coding) with
Kali Linux / Burp Suite / Nuclei (security tooling) into one local,
multi-agent platform, orchestrated by an LLM router with local-model
fallback.

## Surfaces

- CLI
- VS Code extension
- Browser extension (Chrome, later Firefox)
- Desktop app (Tauri) — later phase
- Direct integrations: Burp Suite, Docker, Kali, Git, local APIs

## Full agent roster

Master Agent routing to: Coding, Pentest, Bug Hunting, Reverse Engineering,
SOC, Cloud, IAM, OSINT, Malware, Report, Browser. Detail per agent, and
which are MVP vs. deferred, in docs/AGENTS.md.

## Browser Agent — full passive check list

Headers, CSP, cookies, JWT, local/session storage, CORS, GraphQL, hidden
APIs, JS secrets, Firebase, Supabase, AWS/Azure keys, Stripe/Paystack,
debug endpoints, robots.txt, sitemap.xml, Swagger/OpenAPI, fingerprinting,
WAF detection — then offers active follow-ups (e.g. GraphQL schema
enumeration) as an explicit, gated next step, never automatic
(docs/SECURITY_AND_AUTHORIZATION.md).

## CLI Agent — full active chain

```
nmap → httpx → subfinder → katana → nuclei → ffuf → dalfox → sqlmap
→ custom scripts → LLM analysis
```

The Tool Orchestrator (docs/MVP.md #4) decides the chain per target; the
user doesn't manually pick tools.

## Coding Agent — full flow

Read code → find vulnerabilities → explain → write patch → run tests →
git commit → (opt-in) create PR.

## Memory — full data model

Postgres + pgvector as the single store (docs/REVIEW.md point 3 explains why
this collapsed from three parallel stores): projects, targets, credentials
(reference only — see docs/SECURITY_AND_AUTHORIZATION.md), notes, findings,
exploits, reports, screenshots.

## Browser automation

Playwright-driven authenticated testing: login, click, fill forms, navigate,
capture traffic, analyze. Deferred past MVP — this is powerful and also the
highest-risk surface for accidentally acting on a live account, so it waits
until the scope-gate and audit-log infrastructure (Phase 2) is proven.

## Knowledge base

Continuously indexed, embedded locally: OWASP, MITRE ATT&CK, NIST, CVE,
ExploitDB, GitHub, HackTricks, PayloadsAllTheThings, PortSwigger, Microsoft/
AWS/Azure docs. Feeds the LLM Router's context for both Coding and Pentest
agents.

## Future features (unordered, all post-MVP)

- Voice commands ("Scan this application.")
- Autonomous bug bounty workflows with approval checkpoints
- Malware reverse engineering assistants (sandboxed, no host network access)
- Cloud misconfiguration analysis (AWS, Azure, GCP)
- Infrastructure-as-Code review (Terraform, Kubernetes)
- Active Directory and IAM assessments
- SOC investigation workflows
- Automated report generation with reproducible evidence
- Team collaboration and shared knowledge

## Full original folder structure (target shape, not current)

```
security-ai/
    agents/       (pentest, coding, browser, reverse, soc, cloud, ...)
    tools/        (nuclei, burp, sqlmap, ffuf, katana, subfinder, ...)
    llm/
    memory/
    browser-extension/
    cli/
    api/
    ui/
    docker/
    docs/
```

MVP builds a subset of this (Agent Core lives under `api/` + `agents/`
narrowed to Coding/Pentest/Browser; `tools/` limited to the MVP chain;
`memory/` is Postgres+pgvector only) — see docs/TECH_STACK.md.
