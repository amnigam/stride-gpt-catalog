"""
threatcatalog.llm.provider
==========================

The *raw* model boundary: a single `complete_json` call that takes a system +
user prompt and returns parsed JSON. Two implementations:

* `AnthropicRawLLM` — calls the real Messages API. `anthropic` is imported
  lazily so the package (and the whole deterministic pipeline) has no hard
  dependency on it.
* `StubRawLLM` — returns canned JSON supplied per-call. Used in tests to verify
  the prompt-build → call → Pydantic-validate path without a network.

Wisdom: the model's output is *validated* against our schemas (`LLMArtifactEngine`),
not trusted. A status outside the enum or a malformed score is rejected, not
silently absorbed.
"""

from __future__ import annotations

import json
import re
from typing import Protocol


class RawLLM(Protocol):
    def complete_json(self, system: str, user: str) -> dict | list: ...


class AnthropicRawLLM:
    """Real provider. Requests JSON-only output and parses it.

    `model` defaults to a current Sonnet; override as needed. Strips Markdown
    fences defensively before parsing.
    """

    def __init__(self, api_key: str | None = None,
                 model: str = "claude-sonnet-4-6", max_tokens: int = 4096):
        self.model = model
        self.max_tokens = max_tokens
        self._api_key = api_key

    def complete_json(self, system: str, user: str) -> dict | list:
        import os

        import anthropic  # lazy: only needed on the real path
        client = anthropic.Anthropic(api_key=self._api_key or os.environ.get("ANTHROPIC_API_KEY"))
        msg = client.messages.create(
            model=self.model, max_tokens=self.max_tokens, system=system,
            messages=[{"role": "user", "content": user}])
        text = "".join(b.text for b in msg.content if getattr(b, "type", None) == "text")
        return _parse_json(text)

    def complete_json_image(self, system: str, user: str, image_b64: str,
                            media_type: str = "image/png") -> dict | list:
        import os

        import anthropic
        client = anthropic.Anthropic(api_key=self._api_key or os.environ.get("ANTHROPIC_API_KEY"))
        msg = client.messages.create(
            model=self.model, max_tokens=self.max_tokens, system=system,
            messages=[{"role": "user", "content": [
                {"type": "image", "source": {"type": "base64",
                                             "media_type": media_type, "data": image_b64}},
                {"type": "text", "text": user}]}])
        text = "".join(b.text for b in msg.content if getattr(b, "type", None) == "text")
        return _parse_json(text)


class OpenAIRawLLM:
    """OpenAI / ChatGPT provider — the same `complete_json` seam as Anthropic.

    Use this when your org is standardized on ChatGPT. Nothing else in the
    pipeline changes; only the engine's provider does:

        from threatcatalog.llm import OpenAIRawLLM, LLMArtifactEngine
        engine = LLMArtifactEngine(OpenAIRawLLM(model="gpt-5.2"))

    `openai` is imported lazily (optional dependency). Works with Azure OpenAI
    too by passing `base_url` and an Azure-style deployment as `model`.

    Token-limit parameter: newer models (o-series / GPT-5 family) require
    `max_completion_tokens`; older ones require `max_tokens`. `_create` tries the
    modern name first and falls back automatically, so either generation works.
    """

    def __init__(self, api_key: str | None = None, model: str = "gpt-5.2",
                 base_url: str | None = None, max_tokens: int = 32000):
        self.model = model
        self.max_tokens = max_tokens
        self._api_key = api_key
        self._base_url = base_url

    def _client(self):
        import os

        from openai import OpenAI  # lazy: only needed on the real path
        return OpenAI(api_key=self._api_key or os.environ.get("OPENAI_API_KEY"),
                      base_url=self._base_url)

    def _create(self, client, messages):
        """Call chat.completions, tolerating either token-limit parameter name."""
        try:
            return client.chat.completions.create(
                model=self.model, max_completion_tokens=self.max_tokens, messages=messages)
        except Exception as exc:  # noqa: BLE001 — inspect and retry on the token-param swap only
            msg = str(exc).lower()
            if "max_completion_tokens" in msg or "max_tokens" in msg:
                return client.chat.completions.create(
                    model=self.model, max_tokens=self.max_tokens, messages=messages)
            raise

    def complete_json(self, system: str, user: str) -> dict | list:
        # We do NOT force response_format=json_object: several prompts ask for a
        # top-level JSON *array*, which that mode forbids. _parse_json handles
        # fences/whitespace either way, exactly as on the Anthropic path.
        resp = self._create(self._client(),
                            [{"role": "system", "content": system},
                             {"role": "user", "content": user}])
        return _parse_json(_content_or_raise(resp, self.model))

    def complete_json_image(self, system: str, user: str, image_b64: str,
                            media_type: str = "image/png") -> dict | list:
        resp = self._create(self._client(),
                            [{"role": "system", "content": system},
                             {"role": "user", "content": [
                                 {"type": "text", "text": user},
                                 {"type": "image_url",
                                  "image_url": {"url": f"data:{media_type};base64,{image_b64}"}}]}])
        return _parse_json(_content_or_raise(resp, self.model))


class StubRawLLM:
    """Test double: pops canned responses in order, or returns a single fixed one."""

    def __init__(self, responses: list | dict):
        self._queue = list(responses) if isinstance(responses, list) and responses \
            and isinstance(responses[0], (dict, list)) else None
        self._fixed = responses if self._queue is None else None
        self.calls: list[tuple[str, str]] = []
        self.image_calls: list[tuple[str, str, str]] = []

    def complete_json(self, system: str, user: str) -> dict | list:
        self.calls.append((system, user))
        if self._queue is not None:
            return self._queue.pop(0)
        return self._fixed

    def complete_json_image(self, system: str, user: str, image_b64: str,
                            media_type: str = "image/png") -> dict | list:
        self.image_calls.append((system, user, media_type))
        if self._queue is not None:
            return self._queue.pop(0)
        return self._fixed


class EmptyCompletionError(RuntimeError):
    """The model returned no visible text. Carries the reason, which is the
    whole diagnostic value: `length` means the token budget was exhausted
    (on reasoning models, by reasoning tokens); `content_filter` or a non-null
    refusal means a policy block, and no budget increase will help."""


def _content_or_raise(resp, model: str) -> str:
    """Pull message content, or fail with *why* it was empty."""
    choice = resp.choices[0]
    text = choice.message.content
    if text and text.strip():
        return text
    usage = getattr(resp, "usage", None)
    details = getattr(usage, "completion_tokens_details", None)
    reasoning = getattr(details, "reasoning_tokens", None)
    raise EmptyCompletionError(
        f"{model} returned no content "
        f"(finish_reason={choice.finish_reason!r}, "
        f"refusal={getattr(choice.message, 'refusal', None)!r}, "
        f"completion_tokens={getattr(usage, 'completion_tokens', None)}, "
        f"reasoning_tokens={reasoning}). "
        "finish_reason='length' means the max_tokens budget was consumed before "
        "any visible output — raise max_tokens or reduce the gap size.")


_FENCE_OPEN = re.compile(r"^```[A-Za-z0-9_+-]*[ \t]*\r?\n?")
_FENCE_CLOSE = re.compile(r"\r?\n?```\s*$")


def _parse_json(text: str) -> dict | list:
    text = text.lstrip("\ufeff\u200b").strip()
    if not text:
        raise ValueError("model returned an empty string")
    if text.startswith("```"):
        text = _FENCE_CLOSE.sub("", _FENCE_OPEN.sub("", text)).strip()
    if not text.startswith(("{", "[")):
        # tolerate a prose preamble: seek the first structural character
        starts = [i for i in (text.find("{"), text.find("[")) if i != -1]
        if not starts:
            raise ValueError(f"no JSON found in model output: {text[:200]!r}")
        text = text[min(starts):]
    # raw_decode parses the first complete value and ignores anything trailing
    # (a stray closing fence, a sign-off sentence), which json.loads rejects.
    obj, _end = json.JSONDecoder().raw_decode(text)
    if not isinstance(obj, (dict, list)):
        raise ValueError(f"model output was not a JSON object or array: {text[:200]!r}")
    return obj
