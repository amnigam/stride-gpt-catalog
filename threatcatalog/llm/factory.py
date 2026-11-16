"""
threatcatalog.llm.factory
=========================

One place that turns the UI's engine choice into an `ArtifactEngine`, shared by
the review page and the SAD page so both offer the same providers.
"""

from __future__ import annotations

import os

OPENAI = "OpenAI (ChatGPT)"
ANTHROPIC = "Anthropic (Claude)"
BEDROCK = "AWS Bedrock"
OFFLINE = "Deterministic (offline)"

DEFAULT_MODEL = {OPENAI: "gpt-5.2", ANTHROPIC: "claude-sonnet-4-6", BEDROCK: ""}


def default_model(choice: str) -> str:
    if choice == BEDROCK:
        return os.environ.get("BEDROCK_MODEL_ID", "")
    return DEFAULT_MODEL.get(choice, "")


def build_engine(choice: str, model_id: str = "", api_key: str = "", base_url: str = "",
                 max_tokens: int = 32000, region: str = "", aws_profile: str = ""):
    """Return an LLMArtifactEngine for the chosen provider, or None for offline.

    api_key (from the UI) overrides the environment variable when provided.
    Bedrock uses the standard AWS credential chain; region / profile override it.
    """
    if choice == OPENAI:
        from . import LLMArtifactEngine, OpenAIRawLLM
        return LLMArtifactEngine(OpenAIRawLLM(model=model_id, api_key=api_key or None,
                                              base_url=base_url or None, max_tokens=max_tokens))
    if choice == ANTHROPIC:
        from . import AnthropicRawLLM, LLMArtifactEngine
        return LLMArtifactEngine(AnthropicRawLLM(model=model_id, api_key=api_key or None,
                                                max_tokens=max_tokens))
    if choice == BEDROCK:
        from . import BedrockRawLLM, LLMArtifactEngine
        return LLMArtifactEngine(BedrockRawLLM(
            model=model_id, max_tokens=max_tokens,
            region=region or os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION"),
            profile=aws_profile or None))
    return None  # Deterministic (offline) — pipeline default
