"""
ai_engine/ai_provider.py
Unified AI provider abstraction layer for BlueSentinel v2.0.
Supports OpenAI GPT-4o and Anthropic Claude via switchable backend.
"""
import os
import time
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional

log = logging.getLogger(__name__)


class ConfigurationError(Exception):
    pass


@dataclass
class AIResponse:
    content: str
    model: str
    provider: str
    tokens_used: int
    success: bool
    error: Optional[str] = None


class AIProvider(ABC):
    @abstractmethod
    def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
        max_tokens: int = 1500,
    ) -> AIResponse:
        pass


class OpenAIProvider(AIProvider):
    """OpenAI GPT-4o backend with exponential backoff retry."""

    def __init__(self) -> None:
        self.api_key = os.getenv("OPENAI_API_KEY", "")
        self.model = os.getenv("OPENAI_MODEL", "gpt-4o")
        if not self.api_key:
            raise ConfigurationError(
                "OPENAI_API_KEY is not set. Configure it in .env or environment."
            )

    def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
        max_tokens: int = 1500,
    ) -> AIResponse:
        try:
            import openai
        except ImportError:
            return AIResponse(
                content="",
                model=self.model,
                provider="openai",
                tokens_used=0,
                success=False,
                error="openai package not installed",
            )

        client = openai.OpenAI(api_key=self.api_key)
        last_error: Optional[str] = None

        for attempt in range(3):
            try:
                response = client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    temperature=temperature,
                    max_tokens=max_tokens,
                )
                content = response.choices[0].message.content or ""
                tokens = response.usage.total_tokens if response.usage else 0
                return AIResponse(
                    content=content,
                    model=self.model,
                    provider="openai",
                    tokens_used=tokens,
                    success=True,
                )
            except openai.RateLimitError as exc:
                last_error = str(exc)
                wait = (2 ** attempt) * 2
                log.warning(f"OpenAI rate limit, retrying in {wait}s (attempt {attempt+1}/3)")
                time.sleep(wait)
            except openai.APIConnectionError as exc:
                last_error = str(exc)
                wait = (2 ** attempt) * 1
                log.warning(f"OpenAI connection error, retrying in {wait}s")
                time.sleep(wait)
            except Exception as exc:
                last_error = str(exc)
                log.error(f"OpenAI API error: {exc}")
                break

        return AIResponse(
            content="",
            model=self.model,
            provider="openai",
            tokens_used=0,
            success=False,
            error=last_error,
        )


class ClaudeProvider(AIProvider):
    """Anthropic Claude backend with exponential backoff retry."""

    def __init__(self) -> None:
        self.api_key = os.getenv("ANTHROPIC_API_KEY", "")
        self.model = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-5")
        if not self.api_key:
            raise ConfigurationError(
                "ANTHROPIC_API_KEY is not set. Configure it in .env or environment."
            )

    def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
        max_tokens: int = 1500,
    ) -> AIResponse:
        try:
            import anthropic
        except ImportError:
            return AIResponse(
                content="",
                model=self.model,
                provider="claude",
                tokens_used=0,
                success=False,
                error="anthropic package not installed",
            )

        client = anthropic.Anthropic(api_key=self.api_key)
        last_error: Optional[str] = None

        for attempt in range(3):
            try:
                response = client.messages.create(
                    model=self.model,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    system=system_prompt,
                    messages=[{"role": "user", "content": user_prompt}],
                )
                content = ""
                if response.content and len(response.content) > 0:
                    content = response.content[0].text
                tokens = 0
                if response.usage:
                    tokens = response.usage.input_tokens + response.usage.output_tokens
                return AIResponse(
                    content=content,
                    model=self.model,
                    provider="claude",
                    tokens_used=tokens,
                    success=True,
                )
            except anthropic.RateLimitError as exc:
                last_error = str(exc)
                wait = (2 ** attempt) * 2
                log.warning(f"Claude rate limit, retrying in {wait}s (attempt {attempt+1}/3)")
                time.sleep(wait)
            except anthropic.APIConnectionError as exc:
                last_error = str(exc)
                wait = (2 ** attempt) * 1
                log.warning(f"Claude connection error, retrying in {wait}s")
                time.sleep(wait)
            except Exception as exc:
                last_error = str(exc)
                log.error(f"Claude API error: {exc}")
                break

        return AIResponse(
            content="",
            model=self.model,
            provider="claude",
            tokens_used=0,
            success=False,
            error=last_error,
        )


def get_ai_provider() -> AIProvider:
    """
    Factory: returns configured AI provider based on AI_PROVIDER env var.
    Raises ConfigurationError for unknown providers or missing keys.
    """
    provider = os.getenv("AI_PROVIDER", "openai").lower()
    if provider == "openai":
        return OpenAIProvider()
    elif provider == "claude":
        return ClaudeProvider()
    else:
        raise ConfigurationError(
            f"Unknown AI_PROVIDER: '{provider}'. Valid options: 'openai', 'claude'."
        )
