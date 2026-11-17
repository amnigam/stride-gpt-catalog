"""Shared control explanation used by the catalog page and the details panel."""
from threatcatalog.catalog import Catalog
from threatcatalog.catalog.text import control_markdown


def test_control_markdown_for_reviewers_hides_maintainer_fields():
    c = next(c for c in Catalog.load().controls if c.id == "WEB-CORS-001")
    md = control_markdown(c, heading="", internals=False)
    assert md.startswith("**WEB-CORS-001 — ")
    assert c.intent in md and c.assessment_signal in md
    assert "Detection keywords" not in md and "Expectation" not in md
    full = control_markdown(c)
    assert full.startswith("### WEB-CORS-001") and "Expectation" in full
