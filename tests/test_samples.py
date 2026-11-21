"""The sample applications in testapp/ stay readable and their answer keys
cover exactly the controls the facets select."""

import json
from pathlib import Path

import pytest

from threatcatalog.catalog.loader import load_controls
from threatcatalog.catalog.resolver import resolve
from threatcatalog.models import AICapability, AppProfile, DataClassification, PlatformFacet

ROOT = Path(__file__).resolve().parents[1] / "testapp"
# folder -> (SAD file stem, embedded diagrams, minimum words in the SAD)
SAMPLES = {
    "corvane-supplier-hub": ("Corvane_SupplierHub_SAD_v1.2", 1, 2000),
    "halcyon-claimpilot": ("Halcyon_ClaimPilot_SAD_v2.0", 3, 2000),
    # minimal demo apps: one platform layer each, short SADs
    "marlowe-shift-reporter": ("Marlowe_ShiftReporter_SAD_v1.0", 1, 1500),
    "northfield-sms-reminders": ("Northfield_SMSReminders_SAD_v1.0", 1, 1500),
}
MINIMAL = {"marlowe-shift-reporter": 40, "northfield-sms-reminders": 45}


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
    stem, n_diagrams, min_words = SAMPLES[folder]
    path = ROOT / folder / f"{stem}.docx"
    sad = extract(path.name, path.read_bytes())
    assert sad.words > min_words
    assert len(sad.images) == n_diagrams
    assert not sad.skipped


@pytest.mark.parametrize("folder", MINIMAL)
def test_minimal_demo_apps_stay_small(folder):
    """The demo apps exist to run quickly: one platform layer, no AI, no PCI."""
    key = json.loads((ROOT / folder / "expected_results.json").read_text())
    assert len(key["facets"]["platforms"]) == 1
    assert key["facets"]["ai"] == ["none"] and key["facets"]["pci"] is False
    assert len(key["controls"]) <= MINIMAL[folder]


def test_incomplete_draft_has_no_diagram():
    pytest.importorskip("docx")
    from threatcatalog.sad_extract import extract
    path = ROOT / "corvane-supplier-hub" / "Corvane_SupplierHub_SAD_v0.1_DRAFT_incomplete.docx"
    sad = extract(path.name, path.read_bytes())
    assert not sad.has_diagram
    assert sad.words < 300
