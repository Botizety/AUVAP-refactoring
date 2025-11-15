"""Unit tests for the Gemini client helpers."""

from llm.gemini_client import DEFAULT_MODEL_FALLBACKS, GeminiClient


def _client() -> GeminiClient:
    return GeminiClient(api_key="dummy", base_url="https://example.com/v1beta")


def test_model_candidates_adds_latest_suffix_and_fallbacks() -> None:
    client = _client()
    candidates = client._model_candidates("gemini-2.0-flash")
    assert candidates[:2] == [
        "models/gemini-2.0-flash",
        "models/gemini-2.0-flash-latest",
    ]
    for fallback in DEFAULT_MODEL_FALLBACKS:
        normalized = f"models/{fallback}"
        assert normalized in candidates


def test_model_candidates_respects_prefixed_paths() -> None:
    client = _client()
    candidates = client._model_candidates("models/custom-model")
    assert candidates[:2] == [
        "models/custom-model",
        "models/custom-model-latest",
    ]


def test_build_generate_url_uses_instance_base_url() -> None:
    client = _client()
    url = client._build_generate_url("models/example")
    assert url == "https://example.com/v1beta/models/example:generateContent"


def test_model_candidates_deduplicate_variants() -> None:
    client = GeminiClient(api_key="dummy", fallback_models=["models/custom", "custom", "custom-latest"])
    candidates = client._model_candidates("custom")
    assert candidates[0] == "models/custom"
    # Ensure duplicates removed while '-latest' appended exactly once
    assert candidates.count("models/custom") == 1
    assert candidates.count("models/custom-latest") == 1


def test_strip_markdown_code_fence() -> None:
    client = _client()
    content = """```json
    {"key": "value"}
    ```"""
    assert client._strip_markdown_code_fence(content) == '{"key": "value"}'
