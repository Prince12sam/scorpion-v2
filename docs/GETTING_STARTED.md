# Getting Started

Scorpion is a local-first AI security platform: a Coding Agent (`analyze`/`fix`)
and a Pentest Agent (`scan`, chaining httpx, subfinder, amass, theHarvester,
gau, katana, nmap, nuclei, nikto, testssl.sh, WPScan, ffuf, feroxbuster,
Arjun, dalfox, sqlmap, OWASP ZAP, and a Metasploit auxiliary/scanner
module) behind one CLI, with an LLM router that works with either a cloud
provider or a local model (Ollama). `scan --adaptive` adds an optional
extra phase afterward: an LLM-driven planning loop that picks its own
follow-up actions — including driving a real, sandboxed browser
(navigate/click/fill/extract) — based on what the fixed pipeline found.

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

# sandboxed browser for `scan --adaptive` — also built once from source:
docker build -t scorpion/browser-sandbox:local docker/tools/browser
```

## Run it

```
scorpion launch    # the one command: checks Docker, builds the ffuf/browser-
                    # sandbox images if missing, starts Postgres/Metasploit/
                    # the browser sandbox, starts the Agent Core. Safe to
                    # re-run any time — every step is idempotent, so this is
                    # what to run each time you sit down to use Scorpion.
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
output. Findings are sorted by severity (critical first). If the target was
authorized via `scorpion authorize-sow` and that SOW's own "Deliverables"/
"Reporting" clause specifies what the final report must contain (e.g. "an
executive summary", "a CVSS score per finding"), the report opens with a
checklist of those exact requirements — not an attempt to auto-satisfy each
one (a free-text requirement can't be reliably matched against generated
sections), just a visible reminder of what the SOW actually asked for so it
doesn't get missed when the report is finalized. A "Methodology" section
listing every tool that ran is always included when there are findings,
regardless of what the SOW asks for.

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

`scan` doesn't just check the one host you give it: subfinder, amass,
theHarvester, *and* gau each discover subdomains/URLs independently
(different data sources, so running all of them surfaces more than any
one alone — theHarvester also surfaces non-subdomain OSINT like email
addresses and ASNs, and gau surfaces historical URLs/endpoints/parameters
from third-party archives that live crawling can't find), httpx probes
all of the discovered hosts (one batched call) to find which actually
respond, and
the rest of the pipeline (katana, zap-baseline, nmap, nuclei, nikto,
msf-http-version, testssl, wpscan, ffuf, feroxbuster, arjun, dalfox,
sqlmap, zap-full-scan) runs once per live host — a discovered
`api.example.com` gets the same active scan as `example.com` itself, not
just a line in a subdomain list.
`testssl` (TLS/SSL configuration + known-vulnerability checks) only runs
when the live host actually responded over HTTPS — it's skipped instantly,
not just quickly, for a plain-HTTP host. `wpscan` (WordPress-specific
plugin/theme/user enumeration and known-CVE lookups, with an optional free
API token — `SCORPION_WPSCAN_API_TOKEN`) degrades to no findings just as
quickly against anything that isn't actually WordPress. `arjun` probes
~50 default GET-parameter names for ones that measurably change the
response — undocumented debug/internal flags ffuf/feroxbuster's
path-based wordlists have no way to find.
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

### Adaptive planning loop (`--adaptive`)

`scan --adaptive` runs an extra phase after the fixed pipeline above, not
instead of it: an LLM looks at what's been found so far and decides what
to try next — following an interesting lead, trying a discovered login
form — rather than always running the same tools in the same order. It
can call the same tools the fixed pipeline does (targeted at a specific
URL rather than the whole pipeline), and it can drive a real, sandboxed
Chromium browser (`browser_sandbox`, started by `scorpion launch` like
Postgres/Metasploit): navigate, extract page text/forms, take a
screenshot, click a link/button, or fill a form field. It only ever picks
from a fixed, pre-vetted list of actions — never arbitrary commands — and
every single action re-checks the scope gate independently, same as any
other tool. Clicking/filling (state-changing) needs the `exploitation`
tier — a real SOW via `scorpion authorize-sow`, not self-attestation —
the same boundary already used for sqlmap's impact-confirmation mode.
It stops on its own once the LLM decides there's nothing more worth
trying, after `SCORPION_ADAPTIVE_AGENT_MAX_STEPS` steps (15 by default),
or after `SCORPION_ADAPTIVE_AGENT_STALE_AFTER_STEPS` (3 by default)
consecutive steps that found nothing new — whichever comes first. Because
it's an extra LLM-driven phase on top of an already-thorough fixed
pipeline, expect real added time; it's opt-in for that reason.

#### Trying it locally

`scorpion launch` builds and starts `browser_sandbox` alongside
Postgres/Metasploit — confirm it actually came up before testing anything
else:

```
docker compose -f docker/docker-compose.yml ps    # look for scorpion_browser_sandbox
curl http://localhost:9223/json/version            # Linux/Mac — real Chrome DevTools JSON back
curl.exe http://localhost:9223/json/version        # Windows PowerShell — curl.exe forces the
                                                    # real curl, not the Invoke-WebRequest alias
```

A blank page has nothing interesting for the adaptive loop to act on — spin
up a page with an actual form and link first:

```python
# test_page.py
import http.server
port = 8900
html = b"""<html><body>
<h1>Test Site</h1>
<a href="/admin">Admin Panel</a>
<form action="/login" method="POST">
  <input name="username"><input type="password" name="password">
  <button>Login</button>
</form>
</body></html>"""

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.send_header("Content-Type","text/html"); self.end_headers()
        self.wfile.write(html)

http.server.ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
```

```
python3 test_page.py &                              # Linux/Mac — background job
Start-Process python -ArgumentList "test_page.py"    # Windows PowerShell — separate process
```

Then, since `localhost` auto-verifies (no scope prompt needed):

```
scorpion scan localhost --adaptive --report test_report.md
```

Watch the live progress line — it shows the fixed pipeline's stages
first, then `adaptive: deciding next step`, `adaptive: browser_navigate`,
etc. once that phase starts. Open `test_report.md` afterward for
`[browser]`-tagged findings (discovered form, extracted page text) and
the "Methodology" section. If `SCORPION_CODING_MODELS` isn't configured,
the adaptive phase fails closed to "done" immediately (zero adaptive
steps, no error) — check that first if you see nothing from it.

To see the state-changing actions (`browser_click`/`browser_fill`)
actually execute instead of reporting `skipped — ... not authorized for
action 'exploitation'`, authorize a SOW against the same target first:

```
echo "This SOW authorizes penetration testing of localhost, including exploitation to confirm real impact." > sow.txt
scorpion authorize-sow localhost sow.txt
scorpion scan localhost --adaptive --report test_report2.md
```

(Windows PowerShell: write `sow.txt` with a here-string instead of
`echo >`, to guarantee plain UTF-8 without a stray BOM —
`@'...'@ | Out-File -FilePath sow.txt -Encoding utf8NoBOM`.)

Debugging what the sandboxed browser actually did:

```
docker logs -f scorpion_browser_sandbox   # Chrome/Xvfb's own logs (the dbus
                                           # errors in there are harmless noise)
```

`browser_screenshot` findings write a real PNG to your OS's temp dir —
the `file_path` in that finding is directly openable (e.g.
`/tmp/scorpion-browser-*.png` on Linux/Mac, `$env:TEMP\scorpion-browser-*.png`
on Windows). There's no live-view/VNC yet — extracted text/forms and
screenshots are the only ways to see what it did.

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
  This is also the only way `scan --adaptive`'s state-changing browser
  actions (`browser_click`/`browser_fill`) run instead of reporting
  skipped — same tier, same reasoning. Self-attestation and file-token
  verification can never grant this tier; ambiguous SOW language
  ("penetration test" alone) doesn't either — it fails closed. Requires
  an LLM configured. The full SOW text is stored against the target, same
  accountability principle as a logged self-attestation statement.

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
