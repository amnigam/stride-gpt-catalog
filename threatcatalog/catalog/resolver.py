"""
threatcatalog.catalog.resolver
==============================

Turns an `AppProfile` into the *expected control set*: the union of every
catalog layer the app's facets select.

The key idea is **composition, not enumeration**. We do not maintain one
catalog per app type. Instead each control is tagged with the layers it applies
to, and the resolver computes the union. The AI-capability facet is *tiered*:
selecting a higher tier pulls in the controls of the tiers below it, because an
agentic app is also an LLM-with-tools app is also an LLM app and inherits all
of their risks.
"""

from __future__ import annotations

from ..models import AICapability, AppProfile, Control, Layer, PlatformFacet

PLATFORM_LAYER: dict[PlatformFacet, Layer] = {
    PlatformFacet.WEB: Layer.PLATFORM_WEB,
    PlatformFacet.CLOUD: Layer.PLATFORM_CLOUD,
    PlatformFacet.ONPREM: Layer.PLATFORM_ONPREM,
    PlatformFacet.MOBILE: Layer.PLATFORM_MOBILE,
    PlatformFacet.MULTITENANT: Layer.PLATFORM_SAAS,
    PlatformFacet.API: Layer.PLATFORM_API,
}

# Each AI tier expands to the layers it inherits. MCP and agentic both build on
# 'llm + tools'. Generative is a side-branch (output/provenance risk) that is
# still LLM-based, so it inherits the LLM layer but not the tool/autonomy layers.
AI_INHERITS: dict[AICapability, list[Layer]] = {
    AICapability.NONE: [],
    AICapability.LLM: [Layer.AI_LLM],
    AICapability.LLM_TOOLS: [Layer.AI_LLM, Layer.AI_LLM_TOOLS],
    AICapability.MCP: [Layer.AI_LLM, Layer.AI_LLM_TOOLS, Layer.AI_MCP],
    AICapability.AGENTIC: [Layer.AI_LLM, Layer.AI_LLM_TOOLS, Layer.AI_AGENTIC],
    AICapability.GENERATIVE: [Layer.AI_LLM, Layer.AI_GENERATIVE],
}


def active_layers(profile: AppProfile) -> set[Layer]:
    """The set of catalog layers this app's facets activate. BASE is always on."""
    layers: set[Layer] = {Layer.BASE}
    for p in profile.platforms:
        layers.add(PLATFORM_LAYER[p])
    for cap in profile.ai_capabilities:
        layers.update(AI_INHERITS[cap])
    return layers


def resolve(profile: AppProfile, controls: list[Control]) -> list[Control]:
    """Return the expected controls for ``profile`` — every control whose layers
    intersect the app's active layers, de-duplicated, order-stable."""
    active = active_layers(profile)
    out: list[Control] = []
    seen: set[str] = set()
    for c in controls:
        if c.id in seen:
            continue
        if active.intersection(c.layers):
            out.append(c)
            seen.add(c.id)
    return out
