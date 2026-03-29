"""
tests/py/test_ai_provider.py
pytest tests for ai_engine/ai_provider.py

Tests:
  1. get_ai_provider() returns OpenAIProvider when AI_PROVIDER=openai
  2. get_ai_provider() returns ClaudeProvider when AI_PROVIDER=claude
  3. Invalid provider raises ConfigurationError
  4. AIResponse dataclass populated correctly on mock success
  5. AIResponse.success=False on mock API failure
"""
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))


# ---------------------------------------------------------------------------
# Helpers: mock OpenAI and Anthropic responses
# ---------------------------------------------------------------------------

def _mock_openai_response(content: str = "OK", tokens: int = 3):
    """Build a mock openai ChatCompletion response."""
    mock = MagicMock()
    mock.choices = [MagicMock()]
    mock.choices[0].message.content = content
    mock.usage.total_tokens = tokens
    return mock


def _mock_claude_response(content: str = "OK", input_tokens: int = 2, output_tokens: int = 1):
    """Build a mock anthropic Messages response."""
    mock = MagicMock()
    block = MagicMock()
    block.text = content
    mock.content = [block]
    mock.usage.input_tokens  = input_tokens
    mock.usage.output_tokens = output_tokens
    return mock


# ---------------------------------------------------------------------------
# Fixture: reset config singleton between tests
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def reset_config_singleton():
    """Reset core.config_manager singleton so env vars take effect each test."""
    import core.config_manager as cm
    original = cm._config_instance
    cm._config_instance = None
    yield
    cm._config_instance = original


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """Remove AI provider env vars before each test."""
    for key in ("AI_PROVIDER", "OPENAI_API_KEY", "OPENAI_MODEL",
                "ANTHROPIC_API_KEY", "ANTHROPIC_MODEL"):
        monkeypatch.delenv(key, raising=False)


# ---------------------------------------------------------------------------
# Test 1: get_ai_provider() with AI_PROVIDER=openai
# ---------------------------------------------------------------------------

class TestGetAiProviderOpenai:
    def test_returns_openai_provider(self, monkeypatch):
        """get_ai_provider() returns OpenAIProvider when AI_PROVIDER=openai."""
        monkeypatch.setenv("AI_PROVIDER", "openai")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key")

        from ai_engine.ai_provider import get_ai_provider, OpenAIProvider
        provider = get_ai_provider()
        assert isinstance(provider, OpenAIProvider)

    def test_openai_provider_uses_configured_model(self, monkeypatch):
        """OpenAIProvider reads OPENAI_MODEL from env."""
        monkeypatch.setenv("AI_PROVIDER",   "openai")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key")
        monkeypatch.setenv("OPENAI_MODEL",   "gpt-4o-mini")

        from ai_engine.ai_provider import get_ai_provider
        provider = get_ai_provider()
        assert provider.model == "gpt-4o-mini"

    def test_openai_default_model_is_gpt4o(self, monkeypatch):
        """OpenAIProvider defaults to gpt-4o if OPENAI_MODEL is not set."""
        monkeypatch.setenv("AI_PROVIDER",   "openai")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")

        from ai_engine.ai_provider import get_ai_provider
        provider = get_ai_provider()
        assert provider.model == "gpt-4o"


# ---------------------------------------------------------------------------
# Test 2: get_ai_provider() with AI_PROVIDER=claude
# ---------------------------------------------------------------------------

class TestGetAiProviderClaude:
    def test_returns_claude_provider(self, monkeypatch):
        """get_ai_provider() returns ClaudeProvider when AI_PROVIDER=claude."""
        monkeypatch.setenv("AI_PROVIDER",      "claude")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")

        from ai_engine.ai_provider import get_ai_provider, ClaudeProvider
        provider = get_ai_provider()
        assert isinstance(provider, ClaudeProvider)

    def test_claude_provider_uses_configured_model(self, monkeypatch):
        """ClaudeProvider reads ANTHROPIC_MODEL from env."""
        monkeypatch.setenv("AI_PROVIDER",      "claude")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
        monkeypatch.setenv("ANTHROPIC_MODEL",   "claude-opus-4-5")

        from ai_engine.ai_provider import get_ai_provider
        provider = get_ai_provider()
        assert provider.model == "claude-opus-4-5"

    def test_claude_default_model(self, monkeypatch):
        """ClaudeProvider defaults to claude-sonnet-4-5 if ANTHROPIC_MODEL not set."""
        monkeypatch.setenv("AI_PROVIDER",      "claude")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")

        from ai_engine.ai_provider import get_ai_provider
        provider = get_ai_provider()
        assert provider.model == "claude-sonnet-4-5"


# ---------------------------------------------------------------------------
# Test 3: Invalid provider raises ConfigurationError
# ---------------------------------------------------------------------------

class TestInvalidProvider:
    def test_unknown_provider_raises_config_error(self, monkeypatch):
        """An unknown AI_PROVIDER value raises ConfigurationError."""
        monkeypatch.setenv("AI_PROVIDER", "grok")

        from ai_engine.ai_provider import get_ai_provider, ConfigurationError
        with pytest.raises(ConfigurationError):
            get_ai_provider()

    def test_missing_openai_key_raises_config_error(self, monkeypatch):
        """Missing OPENAI_API_KEY raises ConfigurationError."""
        monkeypatch.setenv("AI_PROVIDER",   "openai")
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)

        from ai_engine.ai_provider import OpenAIProvider, ConfigurationError
        with pytest.raises(ConfigurationError):
            OpenAIProvider()

    def test_missing_anthropic_key_raises_config_error(self, monkeypatch):
        """Missing ANTHROPIC_API_KEY raises ConfigurationError."""
        monkeypatch.setenv("AI_PROVIDER",     "claude")
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

        from ai_engine.ai_provider import ClaudeProvider, ConfigurationError
        with pytest.raises(ConfigurationError):
            ClaudeProvider()


# ---------------------------------------------------------------------------
# Test 4: AIResponse populated correctly on mock success
# ---------------------------------------------------------------------------

class TestAiResponseSuccess:
    def test_openai_response_populated_on_success(self, monkeypatch):
        """AIResponse is fully populated with content, model, provider, tokens."""
        pytest.importorskip("openai")
        monkeypatch.setenv("AI_PROVIDER",   "openai")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key")

        from ai_engine.ai_provider import OpenAIProvider, AIResponse

        mock_client  = MagicMock()
        mock_resp    = _mock_openai_response("AI analysis result", tokens=50)
        mock_client.chat.completions.create.return_value = mock_resp

        with patch("openai.OpenAI", return_value=mock_client):
            provider = OpenAIProvider()
            result   = provider.complete(
                system_prompt="You are a security analyst.",
                user_prompt="Analyse this threat.",
            )

        assert isinstance(result, AIResponse)
        assert result.success       is True
        assert result.content       == "AI analysis result"
        assert result.tokens_used   == 50
        assert result.provider      == "openai"
        assert result.error         is None

    def test_claude_response_populated_on_success(self, monkeypatch):
        """ClaudeProvider AIResponse is populated on success."""
        pytest.importorskip("anthropic")
        monkeypatch.setenv("AI_PROVIDER",      "claude")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")

        from ai_engine.ai_provider import ClaudeProvider, AIResponse

        mock_client = MagicMock()
        mock_resp   = _mock_claude_response("Claude analysis", input_tokens=10, output_tokens=5)
        mock_client.messages.create.return_value = mock_resp

        with patch("anthropic.Anthropic", return_value=mock_client):
            provider = ClaudeProvider()
            result   = provider.complete(
                system_prompt="You are a security expert.",
                user_prompt="Analyse this alert.",
            )

        assert isinstance(result, AIResponse)
        assert result.success     is True
        assert result.content     == "Claude analysis"
        assert result.tokens_used == 15  # 10 + 5
        assert result.provider    == "claude"

    def test_ai_response_includes_model_name(self, monkeypatch):
        """AIResponse.model should match the provider's configured model."""
        pytest.importorskip("openai")
        monkeypatch.setenv("AI_PROVIDER",   "openai")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-key")
        monkeypatch.setenv("OPENAI_MODEL",   "gpt-4o")

        from ai_engine.ai_provider import OpenAIProvider

        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _mock_openai_response()

        with patch("openai.OpenAI", return_value=mock_client):
            provider = OpenAIProvider()
            result   = provider.complete("sys", "user")

        assert result.model == "gpt-4o"


# ---------------------------------------------------------------------------
# Test 5: AIResponse.success=False on mock API failure
# ---------------------------------------------------------------------------

class TestAiResponseFailure:
    def test_openai_api_error_returns_false_success(self, monkeypatch):
        """When OpenAI API raises an exception, success=False and error is set."""
        pytest.importorskip("openai")
        monkeypatch.setenv("AI_PROVIDER",   "openai")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key")

        from ai_engine.ai_provider import OpenAIProvider

        mock_client = MagicMock()
        mock_client.chat.completions.create.side_effect = Exception("Connection refused")

        with patch("openai.OpenAI", return_value=mock_client):
            provider = OpenAIProvider()
            result   = provider.complete("sys", "user")

        assert result.success is False
        assert result.error   is not None
        assert "Connection refused" in result.error
        assert result.content == ""
        assert result.tokens_used == 0

    def test_claude_api_error_returns_false_success(self, monkeypatch):
        """When Claude API raises an exception, success=False and error is set."""
        pytest.importorskip("anthropic")
        monkeypatch.setenv("AI_PROVIDER",      "claude")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")

        from ai_engine.ai_provider import ClaudeProvider

        mock_client = MagicMock()
        mock_client.messages.create.side_effect = Exception("Timeout")

        with patch("anthropic.Anthropic", return_value=mock_client):
            provider = ClaudeProvider()
            result   = provider.complete("sys", "user")

        assert result.success is False
        assert "Timeout" in result.error
        assert result.content == ""

    def test_openai_rate_limit_retries_and_fails(self, monkeypatch):
        """OpenAI RateLimitError triggers retries — after 3 failures returns success=False."""
        openai_module = pytest.importorskip("openai")
        monkeypatch.setenv("AI_PROVIDER",   "openai")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key")

        mock_client = MagicMock()
        mock_rate_limit = openai_module.RateLimitError(
            message="rate_limit",
            response=MagicMock(status_code=429, headers={}),
            body={"error": {"message": "rate limit"}},
        )
        mock_client.chat.completions.create.side_effect = mock_rate_limit

        from ai_engine.ai_provider import OpenAIProvider

        with patch("openai.OpenAI", return_value=mock_client):
            with patch("time.sleep"):  # Don't actually sleep in tests
                provider = OpenAIProvider()
                result   = provider.complete("sys", "user")

        assert result.success is False
        # Should have attempted 3 retries
        assert mock_client.chat.completions.create.call_count == 3

    def test_missing_package_returns_false_success(self, monkeypatch):
        """When openai package is not installed, success=False with helpful error."""
        monkeypatch.setenv("AI_PROVIDER",   "openai")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-key")

        from ai_engine.ai_provider import OpenAIProvider
        provider = OpenAIProvider()

        # Simulate missing import
        import builtins
        real_import = builtins.__import__

        def import_side_effect(name, *args, **kwargs):
            if name == "openai":
                raise ImportError("No module named 'openai'")
            return real_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=import_side_effect):
            result = provider.complete("sys", "user")

        assert result.success is False
        assert result.error   is not None
