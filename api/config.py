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

    semgrep_docker_image: str = "semgrep/semgrep:latest"


settings = Settings()
