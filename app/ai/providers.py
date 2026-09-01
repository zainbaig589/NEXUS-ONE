"""LLM provider abstraction for AI incident investigation.

Providers receive the structured evidence payload built by
``context_builder`` and return the raw response text. Parsing and schema
validation happen downstream in ``validation`` so every provider flows
through the same safety checks.

Two implementations exist:
- ``OpenAICompatibleProvider``: any OpenAI-compatible chat-completions API.
- ``DemoInvestigatorProvider`` (``demo_provider``): deterministic offline
  mock for local development and demos.
"""

import abc
import json
from typing import Any, Dict

import httpx

from app.ai.errors import AIProviderError, AIProviderNotConfiguredError, AIProviderTimeoutError
from app.ai.prompts import build_messages
from app.config import settings


class LLMProvider(abc.ABC):
    """Interface for replaceable investigation providers."""

    name: str = "abstract"

    @abc.abstractmethod
    def investigate(self, context: Dict[str, Any]) -> str:
        """Analyse the evidence payload and return the raw response text."""


class OpenAICompatibleProvider(LLMProvider):
    """Provider for OpenAI-compatible /chat/completions endpoints."""

    name = "openai"

    def __init__(
        self,
        api_key: str,
        model: str,
        base_url: str,
        timeout_seconds: float = 60.0,
    ):
        self.api_key = api_key
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds

    def investigate(self, context: Dict[str, Any]) -> str:
        payload = {
            "model": self.model,
            "messages": build_messages(context),
            "temperature": 0.1,
        }
        url = f"{self.base_url}/chat/completions"
        try:
            response = httpx.post(
                url,
                json=payload,
                headers={"Authorization": f"Bearer {self.api_key}"},
                timeout=self.timeout_seconds,
            )
        except httpx.TimeoutException as exc:
            raise AIProviderTimeoutError(
                f"AI provider did not respond within {self.timeout_seconds} seconds"
            ) from exc
        except httpx.HTTPError as exc:
            raise AIProviderError(
                "AI provider request failed (connection error)"
            ) from exc

        if response.status_code >= 400:
            # Deliberately omit the response body: it may echo request data.
            raise AIProviderError(
                f"AI provider returned HTTP {response.status_code}"
            )

        try:
            content = response.json()["choices"][0]["message"]["content"]
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise AIProviderError(
                "AI provider returned an unexpected response structure"
            ) from exc

        if not isinstance(content, str) or not content.strip():
            raise AIProviderError("AI provider returned an empty response")
        return content


def get_provider() -> LLMProvider:
    """Resolve the configured provider.

    Resolution order:
    - LLM_PROVIDER explicitly "demo" or "openai" (openai requires LLM_API_KEY)
    - otherwise auto: an API key selects the OpenAI-compatible provider
    - otherwise: not configured (clear error, non-AI features unaffected)
    """
    from app.ai.demo_provider import DemoInvestigatorProvider

    provider_name = (settings.LLM_PROVIDER or "").strip().lower()

    if provider_name == "demo":
        return DemoInvestigatorProvider()
    if provider_name == "openai":
        if not settings.LLM_API_KEY:
            raise AIProviderNotConfiguredError(
                "AI investigation is not configured: LLM_PROVIDER is 'openai' but "
                "LLM_API_KEY is not set. Set LLM_API_KEY (and optionally LLM_MODEL / "
                "LLM_BASE_URL), or use LLM_PROVIDER=demo for offline demo mode."
            )
        return OpenAICompatibleProvider(
            api_key=settings.LLM_API_KEY,
            model=settings.LLM_MODEL,
            base_url=settings.LLM_BASE_URL,
            timeout_seconds=settings.LLM_TIMEOUT_SECONDS,
        )

    if settings.LLM_API_KEY:
        return OpenAICompatibleProvider(
            api_key=settings.LLM_API_KEY,
            model=settings.LLM_MODEL,
            base_url=settings.LLM_BASE_URL,
            timeout_seconds=settings.LLM_TIMEOUT_SECONDS,
        )

    raise AIProviderNotConfiguredError(
        "AI investigation is not configured. Set LLM_API_KEY (and optionally "
        "LLM_MODEL / LLM_BASE_URL) to use an OpenAI-compatible provider, or set "
        "LLM_PROVIDER=demo for the deterministic offline demo provider."
    )
