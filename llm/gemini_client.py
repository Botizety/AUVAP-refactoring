"""Google Gemini API client with retry logic and JSON helpers."""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

import requests
from json_repair import repair_json

logger = logging.getLogger("auvap.llm.gemini")

DEFAULT_GEMINI_MODEL = "gemini-2.0-flash"
DEFAULT_BASE_URL = "https://generativelanguage.googleapis.com/v1beta"
DEFAULT_MODEL_FALLBACKS = [
    "gemini-2.0-flash-lite",
    "gemini-2.0-flash-exp",
    "gemini-2.5-flash-lite",
    "gemini-2.5-flash",
    "gemini-2.5-pro",
]


class GeminiAPIError(RuntimeError):
    """Raised for unrecoverable errors returned by the Gemini API."""


class GeminiJSONParseError(ValueError):
    """Raised when a Gemini response cannot be parsed as JSON."""


@dataclass
class GeminiClient:
    """Minimal Gemini client mirroring the OpenRouter client surface."""

    api_key: str
    default_model: str = DEFAULT_GEMINI_MODEL
    base_url: str = DEFAULT_BASE_URL
    fallback_models: Optional[list[str]] = None

    def __post_init__(self) -> None:
        self._session = requests.Session()
        self._session.headers.update({"Content-Type": "application/json"})

    def call(
        self,
        prompt: str,
        temperature: float,
        max_tokens: int,
        model: Optional[str] = None,
        timeout: int = 120,
    ) -> str:
        """Send a prompt to Gemini and return the first candidate string."""

        model_candidates = self._model_candidates(model or self.default_model)
        payload: Dict[str, Any] = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": max(0.0, min(2.0, temperature)),
                "maxOutputTokens": max_tokens,
            },
        }
        params = {"key": self.api_key}

        backoff_schedule = [1, 2, 4]
        attempts = len(backoff_schedule)

        tried_models: list[str] = []
        autodetect_attempted = False

        while True:
            for model_path in model_candidates:
                url = self._build_generate_url(model_path)
                logger.debug("Dispatching Gemini request | model=%s", model_path)
                should_try_next_model = False

                for attempt in range(attempts):
                    try:
                        response = self._session.post(url, params=params, data=json.dumps(payload), timeout=timeout)
                    except requests.Timeout as exc:
                        logger.warning("Gemini timeout (attempt %s/%s)", attempt + 1, attempts)
                        if attempt == attempts - 1:
                            raise TimeoutError("Gemini request timed out") from exc
                        time.sleep(backoff_schedule[attempt])
                        continue
                    except requests.RequestException as exc:
                        logger.warning("Network error calling Gemini: %s", exc)
                        if attempt == attempts - 1:
                            raise GeminiAPIError("Gemini network error") from exc
                        time.sleep(backoff_schedule[attempt])
                        continue

                    if response.status_code in {429, 500, 503}:
                        logger.warning(
                            "Gemini temporary error %s (attempt %s/%s)", response.status_code, attempt + 1, attempts
                        )
                        if attempt == attempts - 1:
                            logger.warning("Gemini model '%s' is unresponsive; trying next model.", model_path)
                            should_try_next_model = True
                            break
                        delay = backoff_schedule[attempt]
                        if response.status_code == 429:
                            delay *= 2
                        time.sleep(delay)
                        continue

                    if response.status_code == 404:
                        logger.warning(
                            "Gemini model not found (%s). If you have access to a '-latest' variant it will be tried next.",
                            model_path,
                        )
                        should_try_next_model = True
                        break

                    if response.status_code >= 400:
                        raise GeminiAPIError(f"Gemini HTTP {response.status_code}: {response.text}")

                    try:
                        data = response.json()
                    except json.JSONDecodeError as exc:
                        raise GeminiAPIError("Gemini returned invalid JSON") from exc

                    try:
                        return self._extract_text(data)
                    except (KeyError, IndexError) as exc:
                        raise GeminiAPIError("Unexpected Gemini response structure") from exc
                    except ValueError as exc:
                        message = str(exc)
                        if "candidate" in message.lower():
                            logger.warning(
                                "Gemini returned empty candidate payload (attempt %s/%s)",
                                attempt + 1,
                                attempts,
                            )
                            if attempt == attempts - 1:
                                logger.warning("Gemini model '%s' is unresponsive; trying next model.", model_path)
                                should_try_next_model = True
                                break
                            time.sleep(backoff_schedule[attempt])
                            continue
                        raise GeminiAPIError("Unexpected Gemini response structure") from exc

                tried_models.append(model_path)
                if should_try_next_model:
                    continue
                
                # This path should ideally not be reached if the loop completes successfully.
                # A successful call returns, and a failed one breaks to the outer loop.
                # We'll add a safeguard here.
                raise GeminiAPIError("Gemini request failed for an unknown reason.")

            if autodetect_attempted:
                break

            autodetected_model = self._discover_generate_content_model(set(tried_models))
            if not autodetected_model:
                break

            autodetect_attempted = True
            logger.info("Gemini auto-discovered supported model '%s'; retrying.", autodetected_model)
            model_candidates = [autodetected_model]

        tried = ", ".join(tried_models or model_candidates)
        raise GeminiAPIError(
            "Gemini could not find a supported model (tried: %s). Set GEMINI_MODEL to a name from the ListModels"
            " endpoint or ensure your API key has access to the requested model." % tried
        )

    def call_with_json_response(self, prompt: str, temperature: float, max_tokens: int) -> Dict[str, Any]:
        attempts = 2
        for attempt in range(attempts):
            content = self.call(prompt=prompt, temperature=temperature, max_tokens=max_tokens)
            cleaned = self._strip_markdown_code_fence(content)
            try:
                return json.loads(cleaned)
            except json.JSONDecodeError as exc:
                fragment = self._extract_json_fragment(cleaned)
                if fragment:
                    try:
                        return json.loads(fragment)
                    except json.JSONDecodeError:
                        pass
                
                try:
                    logger.debug("Attempting JSON repair on malformed Gemini response")
                    repaired = repair_json(cleaned)
                    return json.loads(repaired)
                except Exception as repair_exc:
                    logger.debug("JSON repair failed: %s", repair_exc)
                
                if attempt < attempts - 1:
                    logger.warning("Gemini returned invalid JSON, retrying (%s/%s)...", attempt + 1, attempts)
                    time.sleep(1)
                    continue
                logger.error("Failed to parse JSON from Gemini response: %s", cleaned[:2000])
                raise GeminiJSONParseError("Gemini response is not valid JSON") from exc

    @staticmethod
    def estimate_tokens(text: str) -> int:
        """Return a rough token estimate, mirroring the OpenRouter client."""

        return max(1, len(text) // 4)

    def _build_generate_url(self, model_path: str) -> str:
        base = self.base_url.rstrip("/")
        normalized = model_path.lstrip("/")
        return f"{base}/{normalized}:generateContent"

    def _model_candidates(self, requested_model: str) -> list[str]:
        clean = (requested_model or self.default_model).strip()
        if not clean:
            raise GeminiAPIError("Gemini model name cannot be empty")
        primary = self._normalize_model_path(clean)
        ordered_models = [primary]

        for fallback in self.fallback_models or DEFAULT_MODEL_FALLBACKS:
            fallback_clean = fallback.strip()
            if not fallback_clean:
                continue
            ordered_models.append(self._normalize_model_path(fallback_clean))

        candidates: list[str] = []
        for model_path in ordered_models:
            if model_path not in candidates:
                candidates.append(model_path)
            latest_variant = self._ensure_latest_suffix(model_path)
            if latest_variant not in candidates:
                candidates.append(latest_variant)

        return candidates

    @staticmethod
    def _normalize_model_path(model: str) -> str:
        trimmed = model.lstrip("/")
        if trimmed.startswith("models/") or trimmed.startswith("tunedModels/"):
            return trimmed
        return f"models/{trimmed}"

    @staticmethod
    def _ensure_latest_suffix(model_path: str) -> str:
        if model_path.endswith("-latest"):
            return model_path
        if "/" in model_path:
            prefix, name = model_path.rsplit("/", 1)
            return f"{prefix}/{name}-latest"
        return f"{model_path}-latest"

    @staticmethod
    def _strip_markdown_code_fence(content: str) -> str:
        stripped = content.strip()
        if not stripped.startswith("```"):
            return stripped

        lines = stripped.splitlines()
        if len(lines) < 2:
            return stripped

        body_lines = lines[1:]
        if body_lines and body_lines[-1].strip().startswith("```"):
            body_lines = body_lines[:-1]

        return "\n".join(body_lines).strip()

    def _discover_generate_content_model(self, exclude: set[str]) -> Optional[str]:
        url = f"{self.base_url.rstrip('/')}/models"
        params = {"key": self.api_key, "pageSize": 100}
        try:
            response = self._session.get(url, params=params, timeout=10)
        except requests.RequestException as exc:
            logger.debug("Gemini ListModels request failed: %s", exc)
            return None

        if response.status_code >= 400:
            logger.debug("Gemini ListModels HTTP %s: %s", response.status_code, response.text)
            return None

        try:
            data = response.json()
        except json.JSONDecodeError:
            logger.debug("Gemini ListModels returned invalid JSON")
            return None

        for model_info in data.get("models", []):
            name = model_info.get("name")
            methods = model_info.get("supportedGenerationMethods", [])
            if not name or name in exclude:
                continue
            if "generateContent" in methods:
                return name

        return None

    @staticmethod
    def _extract_text(payload: Dict[str, Any]) -> str:
        candidates = payload.get("candidates") or []
        if not candidates:
            raise ValueError("No candidates in Gemini response")
        parts = candidates[0].get("content", {}).get("parts", [])
        texts = [part.get("text", "") for part in parts if isinstance(part, dict)]
        combined = "\n".join(filter(None, (text.strip() for text in texts)))
        if not combined:
            raise ValueError("Empty Gemini candidate text")
        return combined

    @staticmethod
    def _extract_json_fragment(content: str) -> Optional[str]:
        start = content.find("{")
        end = content.rfind("}")
        if start == -1 or end == -1 or end <= start:
            return None
        return content[start : end + 1]