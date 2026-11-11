"""LLM providers for the /chat endpoint."""
import os
from typing import Protocol

import httpx

LEAK_DEMO_TRIGGER = "leak demo"


class LLMProviderError(Exception):
    """The provider could not produce an answer."""


class LLMProvider(Protocol):
    def complete(self, message: str) -> str: ...


class MockProvider:
    """Deterministic provider for development and tests.

    Echoes a short canned answer. A message containing "leak demo" gets an
    answer that includes sample sensitive data (a public test card number and
    the AWS documentation example key) so output DLP can be demonstrated.
    """

    def complete(self, message: str) -> str:
        if LEAK_DEMO_TRIGGER in message.lower():
            return (
                "Sure, here is the sample data you asked for: "
                "card 4111 1111 1111 1111 and access key AKIAIOSFODNN7EXAMPLE."
            )
        return f"[mock] You said: {message[:100]}"


class OpenAICompatibleProvider:
    """Any server exposing POST {base_url}/chat/completions (OpenAI, Groq,
    Ollama at http://localhost:11434/v1, ...)."""

    def __init__(self, base_url, model, api_key=None, timeout=30.0, transport=None):
        self.url = base_url.rstrip("/") + "/chat/completions"
        self.model = model
        self.api_key = api_key
        self.timeout = timeout
        self.transport = transport  # tests inject httpx.MockTransport

    def complete(self, message: str) -> str:
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": message}],
        }
        try:
            with httpx.Client(timeout=self.timeout, transport=self.transport) as client:
                response = client.post(self.url, json=payload, headers=headers)
            response.raise_for_status()
            content = response.json()["choices"][0]["message"]["content"]
        except (httpx.HTTPError, ValueError, KeyError, IndexError, TypeError) as exc:
            # only the exception type: never leak URLs, headers or bodies upward
            raise LLMProviderError(f"LLM request failed ({type(exc).__name__})") from exc
        if not isinstance(content, str):
            raise LLMProviderError("LLM response had no text content")
        return content


def build_provider_from_env(env=None) -> LLMProvider:
    """Select the provider from LLM_PROVIDER (mock by default).

    Raises ValueError for an unknown provider or a missing LLM_MODEL, so a bad
    configuration stops the app at startup instead of failing per request.
    """
    env = os.environ if env is None else env
    name = (env.get("LLM_PROVIDER") or "mock").strip().lower()
    if name == "mock":
        return MockProvider()
    if name == "openai_compatible":
        model = env.get("LLM_MODEL")
        if not model:
            raise ValueError("LLM_MODEL is required when LLM_PROVIDER=openai_compatible")
        return OpenAICompatibleProvider(
            base_url=env.get("LLM_BASE_URL") or "https://api.openai.com/v1",
            model=model,
            api_key=env.get("LLM_API_KEY") or None,
        )
    raise ValueError(f"unknown LLM_PROVIDER {name!r} (expected 'mock' or 'openai_compatible')")
