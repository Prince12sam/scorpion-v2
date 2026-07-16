from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="SCORPION_", extra="ignore")

    database_url: str = "postgresql+psycopg://es:es_dev_only@localhost:55432/es"

    host: str = "127.0.0.1"
    port: int = 8731
    # `scorpion serve`/`launch` poll /healthz this many times (0.5s apart)
    # before giving up on a fresh start. Confirmed on real hardware: a cold
    # start (first import of langgraph's dependency chain, no warm page
    # cache) can take >10s even though the process itself never hangs or
    # crashes — raise this if you see "Started but not responding yet" with
    # a log that actually shows a clean startup.
    startup_health_check_retries: int = 60

    # Ordered fallback chain for the LLM Router. Each entry is a litellm
    # model string; the router tries them in order until one succeeds.
    # Empty by default — no key is assumed to be configured yet.
    coding_models: list[str] = []
    fast_models: list[str] = []

    # Set via SCORPION_ANTHROPIC_API_KEY / SCORPION_OPENAI_API_KEY / ollama
    # base url etc, or leave to the underlying provider SDKs' own env vars
    # (ANTHROPIC_API_KEY, OPENAI_API_KEY) which litellm reads directly.
    ollama_base_url: str = "http://localhost:11434"
    # litellm's own timeout= isn't reliably enforced for every provider
    # (confirmed: a local Ollama model ran 30+ minutes past this with the
    # old code) — api/llm_router.py additionally wraps every call in a hard
    # wall-clock deadline of its own using this same value. Raise this if
    # you deliberately run large/CPU-only/"thinking" local models.
    llm_call_timeout_seconds: int = 60

    # Coding Agent (Phase 1)
    semgrep_docker_image: str = "semgrep/semgrep:latest"
    semgrep_timeout_seconds: int = 300
    test_run_timeout_seconds: int = 600
    fix_max_findings_per_patch: int = 5

    # Pentest Agent / Tool Orchestrator (Phase 2)
    httpx_docker_image: str = "projectdiscovery/httpx:latest"
    nmap_docker_image: str = "instrumentisto/nmap:latest"
    subfinder_docker_image: str = "projectdiscovery/subfinder:latest"
    katana_docker_image: str = "projectdiscovery/katana:latest"
    nuclei_docker_image: str = "projectdiscovery/nuclei:latest"
    # No maintained official ffuf image exists on Docker Hub — built locally
    # from source instead, see docker/tools/ffuf/Dockerfile.
    ffuf_docker_image: str = "scorpion/ffuf:local"
    dalfox_docker_image: str = "hahwul/dalfox:latest"
    sqlmap_docker_image: str = "googlesky/sqlmap:latest"
    zap_docker_image: str = "zaproxy/zap-stable"

    tool_timeout_seconds: int = 180
    # nuclei's first run per template-cache-volume downloads the templates
    # repo; subsequent runs reuse the cache and are fast, but budget for a
    # cold run.
    nuclei_timeout_seconds: int = 300
    zap_baseline_timeout_seconds: int = 300
    # zap-full-scan actively attacks every spidered page/param, not just a
    # fixed template set like nuclei — genuinely slower on a real site with
    # real content, budget generously.
    zap_full_scan_timeout_seconds: int = 900
    ffuf_wordlist_path: str = "docker/tools/ffuf/wordlist.txt"
    # `scan` enumerates subdomains via subfinder, probes all of them plus the
    # root with httpx, then runs the rest of the pipeline against every host
    # that responds — capped here so one target with hundreds of subdomains
    # can't turn a several-minute scan into a several-hour one. Discovered
    # hosts beyond this count are still reported by subfinder, just not
    # actively scanned; a warning says how many were dropped.
    max_enumerated_hosts: int = 5

    # Every target must reach `verified` status via api/scope.py before any
    # active-scan tool call — see docs/SECURITY_AND_AUTHORIZATION.md.
    scope_verification_ttl_days: int = 30
    # Self-attestation is the weakest verification method (no technical
    # proof of control) — short TTL bounds how long a false or stale
    # attestation stays usable.
    self_attest_ttl_days: int = 1

    # Docker Desktop (Windows/Mac) can't reach the host via localhost/127.0.0.1
    # from inside a container; it exposes the host under this DNS name instead.
    # On Linux Docker (no Docker Desktop), set this to the docker0 gateway IP
    # or run with --network=host and set it to "localhost".
    container_host_alias: str = "host.docker.internal"


settings = Settings()
