"""Loader behaviour: it is the gate, so its failure modes are tested explicitly."""

from __future__ import annotations

import pytest

from threatcatalog.catalog import Catalog, CatalogError, load_controls


def test_loads_shipped_catalog(catalog):
    assert len(catalog) >= 30
    assert catalog.get("AI-PI-001") is not None


def test_missing_dir_raises(tmp_path):
    with pytest.raises(CatalogError):
        load_controls(tmp_path / "does-not-exist")


def test_empty_dir_raises(tmp_path):
    with pytest.raises(CatalogError):
        load_controls(tmp_path)


def test_non_list_top_level_raises(tmp_path):
    (tmp_path / "bad.yaml").write_text("id: not-a-list\n")
    with pytest.raises(CatalogError) as e:
        load_controls(tmp_path)
    assert "list" in str(e.value)


def test_malformed_control_raises_with_file_context(tmp_path):
    (tmp_path / "bad.yaml").write_text(
        "- id: c1\n  title: t\n  intent: i\n  layers: [not-a-layer]\n"
        "  stride: [Spoofing]\n  assessment_signal: '?'\n")
    with pytest.raises(CatalogError) as e:
        load_controls(tmp_path)
    assert "bad.yaml" in str(e.value)


def test_duplicate_id_across_files_raises(tmp_path):
    body = ("- id: DUP\n  title: t\n  intent: i\n  layers: [base]\n"
            "  stride: [Spoofing]\n  assessment_signal: '?'\n")
    (tmp_path / "a.yaml").write_text(body)
    (tmp_path / "b.yaml").write_text(body)
    with pytest.raises(CatalogError) as e:
        load_controls(tmp_path)
    assert "duplicate" in str(e.value).lower()


def test_catalog_get_returns_none_for_unknown(catalog):
    assert catalog.get("NOPE-999") is None
