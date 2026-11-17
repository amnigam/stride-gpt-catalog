"""The two sample applications in testapp/ stay readable and their answer keys
cover exactly the controls the facets select."""

import json
from pathlib import Path

import pytest

from threatcatalog.catalog.loader import load_controls
from threatcatalog.catalog.resolver import resolve
from threatcatalog.models import AICapability, AppProfile, DataClassification, PlatformFacet

ROOT = Path(__file__).resolve().parents[1] / "testapp"
SAMPLES = {
    "corvane-supplier-hub": ("Corvane_SupplierHub_SAD_v1.2", 1),
    "halcyon-claimpilot": ("Halcyon_ClaimPilot_SAD_v2.0", 3),
}


@pytest.mark.parametrize("folder", SAMPLES)
def test_answer_key_matches_resolved_controls(folder):
    key = json.loads((ROOT / folder / "expected_results.json").read_text())
    f = key["facets"]
    profile = AppProfile(name=key["application"],
                         platforms=[PlatformFacet(p) for p in f["platforms"]],
                         ai_capabilities=[AICapability(a) for a in f["ai"]],
                         data_classification=DataClassification(f["data_classification"]),
                         handles_cardholder_data=f["pci"])
    expected = {c.id for c in resolve(profile, load_controls())}
    assert set(key["controls"]) == expected
    statuses = {v["sad_status"].split(" ")[0] for v in key["controls"].values()}
    assert {"implemented", "partial", "not"} <= statuses


@pytest.mark.parametrize("folder", SAMPLES)
def test_sad_docx_extracts_text_and_diagrams(folder):
    pytest.importorskip("docx")
    from threatcatalog.sad_extract import extract
    stem, n_diagrams = SAMPLES[folder]
    path = ROOT / folder / f"{stem}.docx"
    sad = extract(path.name, path.read_bytes())
    assert sad.words > 2000
    assert len(sad.images) == n_diagrams
    assert not sad.skipped


def test_incomplete_draft_has_no_diagram():
    pytest.importorskip("docx")
    from threatcatalog.sad_extract import extract
    path = ROOT / "corvane-supplier-hub" / "Corvane_SupplierHub_SAD_v0.1_DRAFT_incomplete.docx"
    sad = extract(path.name, path.read_bytes())
    assert not sad.has_diagram
    assert sad.words < 300
