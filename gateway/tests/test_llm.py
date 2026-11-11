import httpx
import pytest

from llm import (
    LLMProviderError,
    MockProvider,
    OpenAICompatibleProvider,
    build_provider_from_env,
)


def make_provider(handler, **kwargs):
    """An OpenAI-compatible provider whose HTTP traffic is served by `handler`
    (httpx.MockTransport): no real network."""
    kwargs.setdefault("base_url", "http://llm.test/v1")
    kwargs.setdefault("model", "test-model")
    return OpenAICompatibleProvider(transport=httpx.MockTransport(handler), **kwargs)


def ok_reply(text="hi there"):
    return httpx.Response(200, json={"choices": [{"message": {"role": "assistant", "content": text}}]})


# ------------------------------------------------------------------ mock


def test_mock_provider_is_deterministic():
    provider = MockProvider()
    assert provider.complete("hello") == provider.complete("hello")
    assert provider.complete("hello").startswith("[mock]")


def test_mock_provider_truncates_long_echoes():
    assert len(MockProvider().complete("x" * 1000)) < 200


@pytest.mark.parametrize("message", ["leak demo", "Run the LEAK DEMO please"])
def test_mock_leak_demo_includes_sample_sensitive_data(message):
    answer = MockProvider().complete(message)
    assert "4111 1111 1111 1111" in answer
    assert "AKIAIOSFODNN7EXAMPLE" in answer


# ------------------------------------------------------- openai-compatible


def test_request_shape_and_response_parsing():
    seen = []

    def handler(request):
        seen.append(request)
        return ok_reply("answer")

    provider = make_provider(handler, api_key="test-key")

    assert provider.complete("question") == "answer"
    request = seen[0]
    assert request.method == "POST"
    assert str(request.url) == "http://llm.test/v1/chat/completions"
    assert request.headers["authorization"] == "Bearer test-key"
    assert request.read() == (
        b'{"model":"test-model","messages":[{"role":"user","content":"question"}]}'
    )


def test_no_authorization_header_without_an_api_key():
    seen = []
    provider = make_provider(lambda r: (seen.append(r), ok_reply())[1])
    provider.complete("q")
    assert "authorization" not in seen[0].headers


def test_trailing_slash_in_base_url_is_ignored():
    seen = []
    provider = make_provider(
        lambda r: (seen.append(r), ok_reply())[1], base_url="http://llm.test/v1/"
    )
    provider.complete("q")
    assert str(seen[0].url) == "http://llm.test/v1/chat/completions"


def test_timeout_is_30_seconds_by_default():
    assert make_provider(lambda r: ok_reply()).timeout == 30.0


@pytest.mark.parametrize(
    "handler",
    [
        lambda r: httpx.Response(500, text="upstream exploded"),
        lambda r: httpx.Response(401, json={"error": "bad key"}),
        lambda r: httpx.Response(200, text="not json"),
        lambda r: httpx.Response(200, json={"choices": []}),
        lambda r: httpx.Response(200, json={"unexpected": True}),
        lambda r: httpx.Response(200, json={"choices": [{"message": {"content": None}}]}),
        lambda r: (_ for _ in ()).throw(httpx.ConnectError("refused")),
        lambda r: (_ for _ in ()).throw(httpx.ReadTimeout("slow")),
    ],
    ids=["500", "401", "non-json", "no-choices", "wrong-shape", "null-content", "connect", "timeout"],
)
def test_provider_failures_become_llm_provider_error(handler):
    with pytest.raises(LLMProviderError):
        make_provider(handler).complete("q")


def test_error_message_does_not_leak_the_response_body_or_key():
    provider = make_provider(
        lambda r: httpx.Response(500, text="upstream secret body"), api_key="test-key"
    )
    with pytest.raises(LLMProviderError) as excinfo:
        provider.complete("q")
    assert "upstream secret body" not in str(excinfo.value)
    assert "test-key" not in str(excinfo.value)


# ------------------------------------------------------------- selection


def test_default_provider_is_mock():
    assert isinstance(build_provider_from_env({}), MockProvider)
    assert isinstance(build_provider_from_env({"LLM_PROVIDER": ""}), MockProvider)
    assert isinstance(build_provider_from_env({"LLM_PROVIDER": "MOCK"}), MockProvider)


def test_openai_compatible_is_built_from_the_environment():
    provider = build_provider_from_env({
        "LLM_PROVIDER": "openai_compatible",
        "LLM_BASE_URL": "http://localhost:11434/v1",
        "LLM_MODEL": "llama3",
        "LLM_API_KEY": "test-key",
    })
    assert isinstance(provider, OpenAICompatibleProvider)
    assert provider.url == "http://localhost:11434/v1/chat/completions"
    assert (provider.model, provider.api_key) == ("llama3", "test-key")


def test_openai_compatible_base_url_and_key_have_defaults():
    provider = build_provider_from_env(
        {"LLM_PROVIDER": "openai_compatible", "LLM_MODEL": "m", "LLM_BASE_URL": ""}
    )
    assert provider.url == "https://api.openai.com/v1/chat/completions"
    assert provider.api_key is None


def test_openai_compatible_requires_a_model():
    with pytest.raises(ValueError, match="LLM_MODEL"):
        build_provider_from_env({"LLM_PROVIDER": "openai_compatible"})


def test_unknown_provider_is_rejected():
    with pytest.raises(ValueError, match="unknown LLM_PROVIDER"):
        build_provider_from_env({"LLM_PROVIDER": "carrier-pigeon"})


def test_build_provider_reads_os_environ_by_default(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "mock")
    assert isinstance(build_provider_from_env(), MockProvider)
