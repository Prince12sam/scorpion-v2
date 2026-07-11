# Security & Authorization Model

Leviathan runs active security tooling (nmap, sqlmap, ffuf, nuclei active
templates, authenticated Playwright automation). This doc is the gate that
every one of those tools must pass through before it fires. Read this before
writing any code that calls the Tool Orchestrator or the Pentest/Browser
agents' active paths.

## Core rule

**A conversational "may I?" is not authorization.** An LLM asking the user
"do you want me to enumerate the GraphQL schema?" and getting a "yes" in
chat is a UX confirmation, not a control — it doesn't stop a
misconfigured run, a prompt-injected page, or a scripted/non-interactive
invocation from firing anyway. Authorization must be a technical check the
Tool Router performs, independent of what the LLM decided to say.

## Scope model

Every target (domain, IP range, repo) has a **scope record** in Memory with:

- `status`: `unverified` | `verified` | `revoked`
- `verification_method`: how ownership/authorization was established
- `authorized_actions`: which action classes are allowed (passive-recon,
  active-scan, exploit, authenticated-browsing)
- `expires_at`: scope records expire; stale authorization is treated as none

### Verification methods (any one required to move a target to `verified`)

1. **File token** — place a Leviathan-issued token at
   `https://target/.well-known/leviathan-auth.txt`, same pattern as Google
   Search Console / Burp Suite Enterprise domain verification.
2. **DNS TXT record** — `_leviathan-auth.target` TXT record matching an
   issued token.
3. **Signed engagement record** — for third-party pentest/bug-bounty work,
   the user attaches a scope document (e.g. a bug bounty program's published
   scope, or a signed rules-of-engagement doc) and self-attests; this is the
   weakest method and should be flagged as such in the UI/report, not treated
   as equivalent to file/DNS proof.
4. **Local/private ranges the user's own machine can reach** (RFC1918,
   localhost, explicitly declared lab CIDRs) — treated as pre-verified for
   personal lab use, since there's no third party to harm.

### What the gate blocks

- Any `active-scan` or `exploit` class action against a target that is
  `unverified` or `revoked`, regardless of what the agent's plan says.
- Any action against a target once `expires_at` has passed, until
  re-verified.
- Silent scope expansion — if recon discovers a new subdomain/host, it
  enters as `unverified` and does not inherit the parent domain's scope
  automatically.

### What the gate does not block

- Passive/read-only checks (headers, robots.txt, sitemap.xml, public JS
  parsing, WAF fingerprinting) — these are equivalent to a browser page load
  and carry no additional risk.

## Secrets and data egress

- Anything the Browser Agent or Pentest Agent finds that matches a
  credential/key/token pattern (AWS/Azure/GCP keys, Stripe/Paystack keys,
  JWTs, Firebase/Supabase service keys, generic high-entropy secrets) is
  tagged `sensitive` at the point of discovery.
- `sensitive`-tagged content is redacted before it is included in any prompt
  sent to a cloud LLM. Summarization/explanation of a finding that contains a
  secret happens on a local model, or on a redacted copy.
- Secret *values* are never embedded into pgvector. Memory stores a reference
  (location, type, hash) — the value itself lives in a local encrypted vault
  (e.g. OS keychain or an encrypted-at-rest table with a key not stored in
  the same database).
- Full audit log of every tool invocation: target, action class, scope
  status at time of execution, who/what initiated it. This is what makes the
  eventual Report Agent's evidence trail credible.

## Sandboxing

- Subprocess/container isolation for every external tool the Tool
  Orchestrator runs — no active tool runs with the same privileges as the
  Agent Core process.
- Malware/RE Agent (post-MVP) gets no network access to the host machine,
  full stop — samples are detonated in an isolated sandbox only.

## Legal

This platform is for authorized security testing only: engagements you're
contracted for, programs you're enrolled in, or systems you own. The scope
gate above is the technical enforcement of that; it does not replace having
an actual signed engagement or program scope in hand before testing anything
that isn't your own infrastructure.
