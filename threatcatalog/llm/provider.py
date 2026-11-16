"""
threatcatalog.llm.provider
==========================

The *raw* model boundary: a single `complete_json` call that takes a system +
user prompt and returns parsed JSON. Implementations:

* `AnthropicRawLLM` — calls the real Messages API (streamed, so large output
  budgets work). `anthropic` is imported lazily so the package (and the whole
  deterministic pipeline) has no hard dependency on it.
* `OpenAIRawLLM` — Chat Completions, also for Azure OpenAI / an org gateway.
* `BedrockRawLLM` — AWS Bedrock's Converse API, for any model hosted in the
  organisation's own Bedrock account. Credentials come from the normal AWS chain.
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
    fences defensively before parsing. Calls are STREAMED: the SDK refuses a
    non-streaming request whose output budget could run past ten minutes, which
    any budget above roughly 21k tokens does.
    """

    def __init__(self, api_key: str | None = None,
                 model: str = "claude-sonnet-4-6", max_tokens: int = 32000):
        self.model = model
        self.max_tokens = max_tokens
        self._api_key = api_key

    def _run(self, system: str, content) -> dict | list:
        import os

        import anthropic  # lazy: only needed on the real path
        client = anthropic.Anthropic(api_key=self._api_key or os.environ.get("ANTHROPIC_API_KEY"))
        with client.messages.stream(model=self.model, max_tokens=self.max_tokens, system=system,
                                    messages=[{"role": "user", "content": content}]) as stream:
            msg = stream.get_final_message()
        text = "".join(b.text for b in msg.content if getattr(b, "type", None) == "text")
        stop = getattr(msg, "stop_reason", None)
        if not text.strip() or stop == "max_tokens":
            usage = getattr(msg, "usage", None)
            raise EmptyCompletionError(
                f"{self.model} stopped with stop_reason={stop!r} after "
                f"{getattr(usage, 'output_tokens', None)} output tokens "
                f"(max_tokens={self.max_tokens}). 'max_tokens' means the output budget "
                "ran out — raise max_tokens.")
        return _parse_json(text)

    def complete_json(self, system: str, user: str) -> dict | list:
        return self._run(system, user)

    def complete_json_images(self, system: str, user: str,
                             images: list[tuple[str, str]]) -> dict | list:
        """`images` is a list of (base64 data, media type)."""
        content = [{"type": "image", "source": {"type": "base64", "media_type": mt, "data": b64}}
                   for b64, mt in images]
        content.append({"type": "text", "text": user})
        return self._run(system, content)

    def complete_json_image(self, system: str, user: str, image_b64: str,
                            media_type: str = "image/png") -> dict | list:
        return self.complete_json_images(system, user, [(image_b64, media_type)])


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
        # generous timeout: a large SAD on a reasoning model can think for many minutes
        return OpenAI(api_key=self._api_key or os.environ.get("OPENAI_API_KEY"),
                      base_url=self._base_url, timeout=1800)

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

    def complete_json_images(self, system: str, user: str,
                             images: list[tuple[str, str]]) -> dict | list:
        content = [{"type": "text", "text": user}]
        content += [{"type": "image_url", "image_url": {"url": f"data:{mt};base64,{b64}"}}
                    for b64, mt in images]
        resp = self._create(self._client(),
                            [{"role": "system", "content": system},
                             {"role": "user", "content": content}])
        return _parse_json(_content_or_raise(resp, self.model))

    def complete_json_image(self, system: str, user: str, image_b64: str,
                            media_type: str = "image/png") -> dict | list:
        return self.complete_json_images(system, user, [(image_b64, media_type)])


class BedrockRawLLM:
    """AWS Bedrock provider (Converse API) — one seam for every model hosted in
    the organisation's Bedrock account (Claude, Llama, Mistral, Nova, ...).

    `model` is a Bedrock model id or inference-profile id/ARN. Credentials and
    region come from the standard AWS chain (env vars, ~/.aws, SSO, an instance
    role); `region` / `profile` override it. `boto3` is imported lazily.

    Output budget: models on Bedrock have different output caps. We ask for the
    generous `max_tokens` and, if Bedrock rejects it as above the model's limit,
    retry once at the limit it reports (or half, if it names none) and remember
    that for later calls — so a big default never breaks a smaller model.
    """

    _IMAGE_FORMATS = {"image/png": "png", "image/jpeg": "jpeg", "image/jpg": "jpeg",
                      "image/gif": "gif", "image/webp": "webp"}

    def __init__(self, model: str, region: str | None = None, profile: str | None = None,
                 max_tokens: int = 64000, read_timeout: int = 1800, client=None):
        if not model:
            raise ValueError("Bedrock needs a model id or inference profile "
                             "(e.g. set BEDROCK_MODEL_ID).")
        self.model = model
        self.max_tokens = max_tokens
        self._region = region
        self._profile = profile
        self._read_timeout = read_timeout
        self._client_obj = client               # injected in tests

    def _client(self):
        if self._client_obj is None:
            import boto3  # lazy: only needed on the real path
            from botocore.config import Config
            session = boto3.Session(profile_name=self._profile or None,
                                    region_name=self._region or None)
            self._client_obj = session.client(
                "bedrock-runtime",
                config=Config(read_timeout=self._read_timeout, connect_timeout=30,
                              retries={"max_attempts": 4, "mode": "adaptive"}))
        return self._client_obj

    def _converse(self, system: str, content: list) -> dict | list:
        client = self._client()
        for attempt in range(3):
            try:
                resp = client.converse(
                    modelId=self.model, system=[{"text": system}],
                    messages=[{"role": "user", "content": content}],
                    inferenceConfig={"maxTokens": self.max_tokens})
                break
            except Exception as exc:  # noqa: BLE001 — only the token-cap case is retried
                lower = self._lower_cap(exc)
                if lower is None or attempt == 2:
                    raise
                self.max_tokens = lower
        blocks = (resp.get("output") or {}).get("message", {}).get("content", []) or []
        text = "".join(b.get("text", "") for b in blocks if isinstance(b, dict))
        stop = resp.get("stopReason")
        if not text.strip() or stop == "max_tokens":
            usage = resp.get("usage") or {}
            raise EmptyCompletionError(
                f"{self.model} stopped with stopReason={stop!r} after "
                f"{usage.get('outputTokens')} output tokens (maxTokens={self.max_tokens}). "
                "'max_tokens' means the output budget ran out — raise max_tokens or use a "
                "model with a larger output limit.")
        return _parse_json(text)

    def _lower_cap(self, exc) -> int | None:
        """If `exc` says maxTokens is above the model's limit, the value to retry with."""
        msg = str(exc)
        low = msg.lower()
        if "validation" not in (type(exc).__name__ + low).lower():
            return None
        if not any(k in low for k in ("maxtokens", "max_tokens", "max tokens", "maximum tokens")):
            return None
        nums = [int(n) for n in re.findall(r"\b(\d{3,6})\b", msg) if int(n) < self.max_tokens]
        new = max(nums) if nums else self.max_tokens // 2
        return new if new >= 1024 else None

    def complete_json(self, system: str, user: str) -> dict | list:
        return self._converse(system, [{"text": user}])

    def complete_json_images(self, system: str, user: str,
                             images: list[tuple[str, str]]) -> dict | list:
        import base64
        content = [{"image": {"format": self._IMAGE_FORMATS.get(mt, "png"),
                              "source": {"bytes": base64.b64decode(b64)}}}
                   for b64, mt in images]
        content.append({"text": user})
        return self._converse(system, content)

    def complete_json_image(self, system: str, user: str, image_b64: str,
                            media_type: str = "image/png") -> dict | list:
        return self.complete_json_images(system, user, [(image_b64, media_type)])


class StubRawLLM:
    """Test double: pops canned responses in order, or returns a single fixed one."""

    def __init__(self, responses: list | dict):
        self._queue = list(responses) if isinstance(responses, list) and responses \
            and isinstance(responses[0], (dict, list)) else None
        self._fixed = responses if self._queue is None else None
        self.calls: list[tuple[str, str]] = []
        self.image_calls: list[tuple[str, str, str]] = []
        self.multi_image_calls: list[tuple[str, str, int]] = []

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

    def complete_json_images(self, system: str, user: str,
                             images: list[tuple[str, str]]) -> dict | list:
        for _b64, mt in images:
            self.image_calls.append((system, user, mt))
        self.multi_image_calls.append((system, user, len(images)))
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
