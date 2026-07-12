from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="ES_", extra="ignore")

    database_url: str = "postgresql+psycopg://es:es_dev_only@localhost:55432/es"

    host: str = "127.0.0.1"
    port: int = 8731

    # Ordered fallback chain for the LLM Router. Each entry is a litellm
    # model string; the router tries them in order until one succeeds.
    # Empty by default — no key is assumed to be configured yet.
    coding_models: list[str] = []
    fast_models: list[str] = []

    # Set via ES_ANTHROPIC_API_KEY / ES_OPENAI_API_KEY / ollama base url etc,
    # or leave to the underlying provider SDKs' own env vars
    # (ANTHROPIC_API_KEY, OPENAI_API_KEY) which litellm reads directly.
    ollama_base_url: str = "http://localhost:11434"

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
    ffuf_docker_image: str = "es/ffuf:local"
    dalfox_docker_image: str = "hahwul/dalfox:latest"
    sqlmap_docker_image: str = "googlesky/sqlmap:latest"

    tool_timeout_seconds: int = 180
    # nuclei's first run per template-cache-volume downloads the templates
    # repo; subsequent runs reuse the cache and are fast, but budget for a
    # cold run.
    nuclei_timeout_seconds: int = 300
    ffuf_wordlist_path: str = "docker/tools/ffuf/wordlist.txt"

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
