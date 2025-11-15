"""OpenRouter API client with retry logic and JSON helpers."""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import requests

logger = logging.getLogger("auvap.llm.openrouter")

DEFAULT_MODEL = "tngtech/deepseek-r1t2-chimera:free"
DEFAULT_BASE_URL = "https://openrouter.ai/api/v1/chat/completions"


class APIError(RuntimeError):
    """Raised for unrecoverable errors returned by the OpenRouter API."""


class JSONParseError(ValueError):
    """Raised when an LLM response cannot be parsed as JSON."""


@dataclass
class OpenRouterClient:
    """Lightweight wrapper around the OpenRouter chat completions endpoint."""

    api_key: str
    default_model: str = DEFAULT_MODEL
    base_url: str = DEFAULT_BASE_URL

    def __post_init__(self) -> None:
        self._session = requests.Session()
        self._session.headers.update(
            {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
        )

    # Public API -----------------------------------------------------------------
    def call(
        self,
        prompt: str,
        temperature: float,
        max_tokens: int,
        model: Optional[str] = None,
        timeout: int = 120,
    ) -> str:
        """Send a prompt to OpenRouter and return the first choice text."""

        payload = {
            "model": model or self.default_model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        logger.debug("Dispatching OpenRouter request | model=%s", payload["model"])

        backoff_schedule = [1, 2, 4]
        attempts = len(backoff_schedule)

        for attempt in range(attempts):
            try:
                response = self._session.post(
                    self.base_url,
                    data=json.dumps(payload),
                    timeout=timeout,
                )
            except requests.Timeout as exc:
                logger.warning("OpenRouter timeout (attempt %s/%s)", attempt + 1, attempts)
                if attempt == attempts - 1:
                    raise TimeoutError("OpenRouter request timed out") from exc
                time.sleep(backoff_schedule[attempt])
                continue
            except requests.RequestException as exc:
                logger.warning("Network error calling OpenRouter: %s", exc)
                if attempt == attempts - 1:
                    raise APIError("OpenRouter network error") from exc
                time.sleep(backoff_schedule[attempt])
                continue

            if response.status_code == 401:
                raise APIError("Invalid OpenRouter API key")

            if response.status_code in {429, 500, 503}:
                logger.warning(
                    "OpenRouter temporary error %s (attempt %s/%s)",
                    response.status_code,
                    attempt + 1,
                    attempts,
                )
                if attempt == attempts - 1:
                    raise APIError(f"OpenRouter service unavailable ({response.status_code})")
                delay = backoff_schedule[attempt]
                if response.status_code == 429:
                    delay *= 2
                time.sleep(delay)
                continue

            if response.status_code >= 400:
                raise APIError(f"OpenRouter HTTP {response.status_code}: {response.text}")

            try:
                data = response.json()
            except json.JSONDecodeError as exc:
                raise APIError("OpenRouter returned invalid JSON") from exc

            try:
                return data["choices"][0]["message"]["content"].strip()
            except (KeyError, IndexError) as exc:
                raise APIError("Unexpected OpenRouter response structure") from exc

        raise APIError("OpenRouter retry logic exhausted")

    def call_with_json_response(
        self, prompt: str, temperature: float, max_tokens: int
    ) -> Dict[str, Any]:
        """Call OpenRouter and parse the response content as JSON."""

        attempts = 2
        for attempt in range(attempts):
            content = self.call(prompt=prompt, temperature=temperature, max_tokens=max_tokens)
            cleaned = self._strip_code_fences(content)
            try:
                return json.loads(cleaned)
            except json.JSONDecodeError as exc:
                fragment = self._extract_json_fragment(cleaned)
                if fragment:
                    try:
                        return json.loads(fragment)
                    except json.JSONDecodeError:
                        pass
                if attempt < attempts - 1:
                    logger.warning("LLM returned invalid JSON, retrying (%s/%s)...", attempt + 1, attempts)
                    time.sleep(1)
                    continue
                logger.error("Failed to parse JSON from LLM response: %s", cleaned[:2000])
                raise JSONParseError("LLM response is not valid JSON") from exc

    @staticmethod
    def estimate_tokens(text: str) -> int:
        """Return a rough token estimate assuming 1 token ~= 4 characters."""

        return max(1, len(text) // 4)

    # Internal helpers -----------------------------------------------------------
    @staticmethod
    def _strip_code_fences(content: str) -> str:
        """Remove Markdown code fences (```json ... ``` ) if present."""

        text = content.strip()
        tagged = OpenRouterClient._extract_tagged_payload(text)
        if tagged is not None:
            return tagged

        lines = text.splitlines()
        if len(lines) >= 2 and lines[0].startswith("```") and lines[-1].startswith("```"):
            return "\n".join(lines[1:-1]).strip()
        return text

    @staticmethod
    def _extract_tagged_payload(content: str) -> Optional[str]:
        markers = [
            ("<json>", "</json>"),
            ("<JSON>", "</JSON>"),
            ("BEGIN_JSON", "END_JSON"),
            ("<<JSON>>", "<<END_JSON>>"),
        ]
        for start, end in markers:
            start_idx = content.find(start)
            end_idx = content.rfind(end)
            if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
                segment = content[start_idx + len(start) : end_idx].strip()
                if segment:
                    return segment
        return None

    @staticmethod
    def _extract_json_fragment(content: str) -> Optional[str]:
        """Return substring spanning the first '{' to the last '}' if ordered properly."""

        start = content.find("{")
        end = content.rfind("}")
        if start == -1 or end == -1 or end <= start:
            return None
        return content[start : end + 1]
