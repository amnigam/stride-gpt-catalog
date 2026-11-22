"""The Help page's References tab is generated from the catalog."""

from threatcatalog.catalog.loader import load_controls
from threatcatalog.references import FRAMEWORKS, framework_rows, pci_row


def test_every_catalog_framework_is_described_with_a_source():
    rows = framework_rows(load_controls())
    keys = {r["key"] for r in rows}
    assert keys <= set(FRAMEWORKS), keys - set(FRAMEWORKS)   # no undocumented framework
    assert all(r["url"].startswith("https://") and r["version"] for r in rows)
    cis = next(r for r in rows if r["key"] == "cis_v8")
    assert cis["controls"] == len(load_controls())            # CIS is on every control
    asi = next(r for r in rows if r["key"] == "owasp_asi")
    assert "ASI07:2026" in asi["refs"] and "ASI-AUTH-001" in asi["refs"]["ASI07:2026"]


def test_pci_row_lists_requirements_in_numeric_order():
    p = pci_row(load_controls())
    reqs = list(p["refs"])
    assert p["version"] == "v4.0.1" and p["controls"] > 0
    assert reqs.index("6.4.3") < reqs.index("10.2.1")
    assert "SEC-SECRETS-001" in p["refs"]["8.6.2"]
