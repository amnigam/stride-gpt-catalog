"""Resolver: composition + AI-tier inheritance are the heart of 'app-type aware'."""

from __future__ import annotations

from threatcatalog.catalog import active_layers, resolve
from threatcatalog.models import (AICapability, AppProfile, DataClassification,
                                  Layer, PlatformFacet)


def _profile(platforms, ai):
    return AppProfile(name="x", platforms=platforms, ai_capabilities=ai,
                      data_classification=DataClassification.INTERNAL)


def test_base_always_active():
    layers = active_layers(_profile([PlatformFacet.WEB], [AICapability.NONE]))
    assert Layer.BASE in layers


def test_web_only_excludes_cloud(catalog):
    p = _profile([PlatformFacet.WEB], [AICapability.NONE])
    ids = {c.id for c in resolve(p, catalog.controls)}
    assert "WEB-WAF-001" in ids
    assert "CLD-SEG-001" not in ids


def test_ai_llm_tools_inherits_llm():
    layers = active_layers(_profile([PlatformFacet.WEB], [AICapability.LLM_TOOLS]))
    assert {Layer.AI_LLM, Layer.AI_LLM_TOOLS} <= layers
    assert Layer.AI_MCP not in layers


def test_ai_agentic_inherits_full_stack():
    layers = active_layers(_profile([PlatformFacet.WEB], [AICapability.AGENTIC]))
    assert {Layer.AI_LLM, Layer.AI_LLM_TOOLS, Layer.AI_AGENTIC} <= layers


def test_mcp_inherits_tools_and_llm():
    layers = active_layers(_profile([PlatformFacet.WEB], [AICapability.MCP]))
    assert {Layer.AI_LLM, Layer.AI_LLM_TOOLS, Layer.AI_MCP} <= layers
    assert Layer.AI_AGENTIC not in layers


def test_generative_is_side_branch_inheriting_llm_only():
    layers = active_layers(_profile([PlatformFacet.WEB], [AICapability.GENERATIVE]))
    assert {Layer.AI_LLM, Layer.AI_GENERATIVE} <= layers
    assert Layer.AI_LLM_TOOLS not in layers


def test_agentic_app_resolves_superset_of_llm_app(catalog):
    llm = {c.id for c in resolve(_profile([PlatformFacet.WEB], [AICapability.LLM]), catalog.controls)}
    agentic = {c.id for c in resolve(_profile([PlatformFacet.WEB], [AICapability.AGENTIC]), catalog.controls)}
    assert llm < agentic  # strict superset


def test_resolution_is_deduplicated(catalog):
    # selecting overlapping facets must not double-count a control
    p = _profile([PlatformFacet.WEB, PlatformFacet.CLOUD],
                 [AICapability.LLM, AICapability.GENERATIVE])
    resolved = resolve(p, catalog.controls)
    ids = [c.id for c in resolved]
    assert len(ids) == len(set(ids))


def test_multi_platform_unions_layers(catalog):
    p = _profile([PlatformFacet.WEB, PlatformFacet.MOBILE], [AICapability.NONE])
    ids = {c.id for c in resolve(p, catalog.controls)}
    assert "WEB-WAF-001" in ids and "MOB-PIN-001" in ids
