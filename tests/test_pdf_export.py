"""PDF export — verifies a valid PDF is produced. Skips if reportlab absent."""

from __future__ import annotations

import pytest

from threatcatalog import pipeline
from threatcatalog.models import (AICapability, AppProfile, DataClassification,
                                  ObservedControl, PlatformFacet)

pytest.importorskip("reportlab")
from threatcatalog.pdf_export import render_pdf   # noqa: E402


def _report(declared_missing_ai):
    profile = AppProfile(name="PeopleDesk", platforms=[PlatformFacet.WEB, PlatformFacet.CLOUD],
                         ai_capabilities=[AICapability.LLM],
                         data_classification=DataClassification.RESTRICTED)
    return pipeline.run(profile, description="Okta SSO; encrypted at rest; TLS 1.3; WAF.",
                        declared=declared_missing_ai,
                        observed_unmatched=[ObservedControl(name="tokenization",
                                                            description="masks pii")])


def test_render_pdf_returns_valid_pdf_bytes(declared_missing_ai):
    pdf = render_pdf(_report(declared_missing_ai))
    assert isinstance(pdf, bytes)
    assert pdf.startswith(b"%PDF-")
    assert len(pdf) > 2000          # non-trivial document


def test_render_pdf_handles_empty_report(catalog):
    # bare profile, no evidence -> all unknown; PDF must still build
    profile = AppProfile(name="Bare", platforms=[PlatformFacet.WEB],
                         ai_capabilities=[AICapability.NONE])
    pdf = render_pdf(pipeline.run(profile, controls=catalog.controls))
    assert pdf.startswith(b"%PDF-")
