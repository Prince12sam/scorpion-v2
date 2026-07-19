# Getting Started

Scorpion is a local-first AI security platform: a Coding Agent (`analyze`/`fix`)
and a Pentest Agent (`scan`, chaining httpx, subfinder, amass, katana, nmap,
nuclei, nikto, testssl.sh, WPScan, ffuf, feroxbuster, dalfox, sqlmap, OWASP
ZAP, and a Metasploit auxiliary/scanner module) behind one CLI, with an LLM
router that works with either a cloud provider or a local model (Ollama).

Written and verified on Windows and Linux — see docs/WINDOWS.md /
docs/LINUX.md for what's different (and what actually went wrong and got
fixed) on each.

## Prerequisites

- Python 3.11+
- Docker running — every external security tool (including semgrep, which
  has no native Windows build) runs sandboxed in a container. On
  Windows/Mac that's Docker Desktop; on Linux, the native Docker daemon
  (see docs/LINUX.md — no Docker Desktop needed, and fewer setup quirks
  than Windows)

## Setup

```
python -m venv .venv

.venv\Scripts\activate           # Windows
source .venv/bin/activate        # Linux/Mac

pip install -r requirements.txt
pip install -e .                 # registers the `scorpion` command (pyproject.toml)

cp .env.example .env             # then fill in SCORPION_CODING_MODELS + a provider key
                                  # (optional — analyze/fix work without one,
                                  # just without LLM summaries/patches)

cd docker
cp .env.example .env              # set real ES_PG_PASSWORD/MSF_PG_PASSWORD/MSF_RPC_PASSWORD —
                                  # compose refuses to start without them
docker compose up -d              # starts Postgres+pgvector, Metasploit's own
                                  # Postgres, and msfrpcd (localhost:55432/55553)
cd ..

# ffuf has no maintained official Docker image — build it once from source:
docker build -t scorpion/ffuf:local docker/tools/ffuf
```

## Run it

```
scorpion launch    # the one command: checks Docker, starts Postgres if
                    # needed, builds the ffuf image if missing, starts the
                    # Agent Core. Safe to re-run any time — every step is
                    # idempotent, so this is what to run each time you sit
                    # down to use Scorpion.
```

Or manage the Agent Core on its own:

```
scorpion serve              # starts detached, tracked by a PID file
scorpion status             # check it's up and healthy
scorpion stop                # stop it cleanly
scorpion serve --foreground  # or run attached to this terminal instead
```

On first startup it creates the `vector` extension and all Postgres
tables if they don't exist yet.

## Use the CLI

```
scorpion analyze path/to/code
scorpion fix path/to/repo              # proposes a patch, doesn't touch disk
scorpion fix path/to/repo --apply       # writes the patch, runs pytest
scorpion fix path/to/repo --apply --commit   # + commits if tests pass

scorpion scan localhost                # local/private targets auto-verify, scans immediately
scorpion scan some-target.example       # prompts for self-attestation (see below)
scorpion verify-target some-target.example --token <token>   # stronger, provable verification

scorpion scan-api some-target.example --spec openapi.json                  # test every endpoint the spec declares
scorpion scan-api some-target.example --spec openapi.json \
  --auth-header "Authorization: Bearer <token>"                            # authenticated endpoints too
```

Add `--report path/to/file.md` to `analyze`, `scan`, or `scan-api` to also
write the findings, summary, and warnings to a Markdown file — useful for a
bug bounty submission or client deliverable instead of copying terminal
output. Findings are sorted by severity (critical first).

Findings are also correlated before display: a real scan often has
several tools flag the same underlying issue on the same URL (e.g.
zap-baseline and zap-full-scan both noting a missing security header) —
these merge into one entry noting which tools confirmed it, instead of
listing the same issue N times. This is heuristic (URL + category
matching), not certain — anything it can't confidently match, including
`analyze`'s file-path-based semgrep findings, passes through unchanged
rather than risking a wrong merge.

### Testing API endpoints specifically

`scan`'s tools (katana, zap-baseline/full-scan, nuclei, ffuf, dalfox,
sqlmap) only reach endpoints reachable by crawling or fuzzing an
unauthenticated GET — most real API routes (POST-only, behind login, JSON
bodies) are invisible to that. `scan-api` uses OWASP ZAP's zap-api-scan
against an OpenAPI/Swagger definition instead: it reads every declared
endpoint/parameter and tests each directly, with `--auth-header` injecting
a token/header into every request so authenticated routes are reachable
too. `--spec` accepts a URL or a local file path. `--target-url` overrides
the API host from the spec if it isn't directly reachable from inside the
scan container.

Every long-running command (`analyze`, `fix`, `scan`, `scan-api`) shows a
live spinner with the current stage and elapsed time rather than sitting
silent — a real `scan` against a content-heavy site can take several
minutes end-to-end (nuclei alone can run ~3000 requests), and a terminal
showing nothing for that long is indistinguishable from a hang.

### Enumeration

`scan` doesn't just check the one host you give it: subfinder *and* amass
each discover subdomains independently (different passive data sources,
so running both surfaces more real subdomains than either alone), httpx
probes all of them (one batched call) to find which actually respond, and
the rest of the pipeline (katana, zap-baseline, nmap, nuclei, nikto,
msf-http-version, testssl, wpscan, ffuf, feroxbuster, dalfox, sqlmap,
zap-full-scan) runs once per live host — a discovered `api.example.com`
gets the same active scan as `example.com` itself, not just a line in a
subdomain list.
`testssl` (TLS/SSL configuration + known-vulnerability checks) only runs
when the live host actually responded over HTTPS — it's skipped instantly,
not just quickly, for a plain-HTTP host. `wpscan` (WordPress-specific
plugin/theme/user enumeration and known-CVE lookups, with an optional free
API token — `SCORPION_WPSCAN_API_TOKEN`) degrades to no findings just as
quickly against anything that isn't actually WordPress.
zap-full-scan is by far the slowest stage (it actively attacks every
spidered page/param rather than a fixed template set) — expect several
extra minutes per host versus nuclei alone. `msf-http-version` needs
Metasploit's RPC daemon up (`scorpion launch` handles this, or `docker
compose up msf_rpc` directly) — if it isn't reachable yet, that stage just
reports skipped/failed like any other tool outage, the rest of the scan
still runs. This is capped at 5 hosts by default
(`SCORPION_MAX_ENUMERATED_HOSTS`) to bound how long a scan takes and how
much a single target gets hit; anything beyond the cap is still reported
by subfinder/amass, just not actively scanned, and the warnings say how
many were dropped. Discovered subdomains inherit the root target's scope
verification automatically — re-verifying every subdomain individually
isn't required.

## Scanning a target you don't own

`scan` only runs against targets a scope gate has verified — a
conversational "yes" is never enough, this is enforced in code before any
active tool fires. `localhost` and RFC1918 addresses auto-verify since
there's no third party to harm. For anything else, `scan` gives you two
paths:

- **Self-attestation (quick, weaker)** — `scan` prompts you interactively:
  confirm you own/are authorized to test the target, then type a short
  statement of that authorization. Both are logged against the target (a
  false attestation is attributable later, unlike an unlogged chat "yes")
  and the verification expires after 1 day by default
  (`SCORPION_SELF_ATTEST_TTL_DAYS`) — short on purpose, since there's no
  technical proof behind it. For scripting, skip the prompt with
  `scan <target> --self-attest "reason"`.
- **File-token (slower, provable)** — pick any token string, place it at
  `https://<target>/.well-known/scorpion-auth.txt` on the target itself
  (proving you control it), then run `verify-target <target> --token <same
  string>`. Verification lasts 30 days (`SCORPION_SCOPE_VERIFICATION_TTL_DAYS`).

Either way, an unverified target isn't scanned — the CLI reports it as
skipped, per stage, until one of the above succeeds. Active-scan tools
(nmap, nuclei, ffuf, dalfox, sqlmap) send real requests/payloads — only
authorize something you're actually allowed to test.

- **SOW (strongest, unlocks exploitation)** — `scorpion authorize-sow
  <target> <path-to-sow-file>` reads a real Statement of Work; an LLM
  extracts only what it explicitly grants. This is the only path that can
  additionally unlock the **exploitation** tier: when a SOW explicitly
  authorizes confirming a vulnerability's real impact (not just detecting
  it), sqlmap escalates to enumerate the current database, DBMS version
  banner, and available database names — proof of impact, never full data
  extraction (`--dump`) or shell access, which this doesn't implement.
  Self-attestation and file-token verification can never grant this tier;
  ambiguous SOW language ("penetration test" alone) doesn't either — it
  fails closed. Requires an LLM configured. The full SOW text is stored
  against the target, same accountability principle as a logged
  self-attestation statement.

## Without an LLM key configured

`analyze` still runs semgrep and returns raw findings; the summary field
explains that no LLM is configured instead of a real summary. `fix` requires
an LLM (semgrep alone doesn't write patches) and will return a clear error
if none is configured. Every LLM call — cloud or local — is bounded by a
hard timeout (`SCORPION_LLM_CALL_TIMEOUT_SECONDS`, default 60s) enforced in
code, independent of whether the underlying provider honors its own timeout
setting.

## Notes

- `fix --apply` assumes `path` is a git repository (uses `git apply` / `git
  commit`). Commit is opt-in and only happens if `pytest` passes after the
  patch is applied.
- Findings are persisted to Memory (Postgres) keyed by project name. If
  Postgres isn't reachable, `analyze`/`fix` still work — you just won't get
  cross-session recall of past findings.
- **Give Docker at least ~6-8GB of RAM.** With Docker Desktop's default
  ~2GB, `scan`'s later stages (nuclei, dalfox, sqlmap running back to back
  against a real site) got erratic multi-minute to hour-long hangs under
  memory pressure — not a code bug, the containers themselves were
  starved. Docker Desktop: Settings → Resources → Memory. Native Linux
  Docker isn't capped the same way by default, but the same tools still
  need real memory to run several at once without contention.
- If you scan the same real site again immediately after a full pass,
  expect thinner results: many sites start rate-limiting/blocking after an
  intensive scan, which is the target defending itself, not a bug here.
