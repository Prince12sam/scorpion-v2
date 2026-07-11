import litellm

from api.config import settings

litellm.suppress_debug_info = True


class LLMUnavailable(Exception):
    pass


def complete(messages: list[dict], purpose: str = "coding") -> str:
    """Try each configured model in order, return the first success.

    Empty config (the default) means no provider has been set up yet —
    callers must handle LLMUnavailable rather than treat it as a crash,
    since the rest of the pipeline (e.g. semgrep findings) is still useful
    without an LLM summary.
    """
    models = settings.coding_models if purpose == "coding" else settings.fast_models
    if not models:
        raise LLMUnavailable(
            "No LLM provider configured. Set ES_CODING_MODELS (and the "
            "matching provider API key) in .env — see docs/GETTING_STARTED.md"
        )

    last_err: Exception | None = None
    for model in models:
        try:
            response = litellm.completion(
                model=model,
                messages=messages,
                timeout=60,
                api_base=settings.ollama_base_url if model.startswith("ollama/") else None,
            )
            return response.choices[0].message["content"]
        except Exception as exc:  # noqa: BLE001 - deliberately broad, this is a fallback chain
            last_err = exc
            continue

    raise LLMUnavailable(f"All configured LLM providers failed. Last error: {last_err}")
