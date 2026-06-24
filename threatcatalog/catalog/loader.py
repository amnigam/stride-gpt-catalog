"""
threatcatalog.catalog.loader
============================

Loads the layered YAML catalog into validated `Control` objects. The loader is
the *gate*: catalog authors edit YAML, and a malformed entry (bad layer, bad
STRIDE value, mis-shaped PCI ref, unknown key) fails at load time rather than
producing a broken threat model later. This is deliberate — fail loud, fail early.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import ValidationError

from ..models import Control

DATA_DIR = Path(__file__).parent / "data"


class CatalogError(Exception):
    """Raised when the catalog cannot be loaded or is internally inconsistent."""


def load_controls(data_dir: Path | None = None) -> list[Control]:
    """Load and validate every control from every YAML file in ``data_dir``.

    Raises ``CatalogError`` with a precise message on the first malformed entry
    or on a duplicate control id across the whole catalog.
    """
    data_dir = data_dir or DATA_DIR
    if not data_dir.is_dir():
        raise CatalogError(f"catalog data directory not found: {data_dir}")

    controls: list[Control] = []
    seen: dict[str, str] = {}  # id -> file it first appeared in

    for path in sorted(data_dir.glob("*.yaml")):
        raw = yaml.safe_load(path.read_text()) or []
        if not isinstance(raw, list):
            raise CatalogError(f"{path.name}: top-level YAML must be a list of controls")
        for i, entry in enumerate(raw):
            try:
                control = Control.model_validate(entry)
            except ValidationError as exc:
                raise CatalogError(f"{path.name} entry #{i + 1}: {exc}") from exc
            if control.id in seen:
                raise CatalogError(
                    f"duplicate control id {control.id!r} in {path.name} "
                    f"(first seen in {seen[control.id]})"
                )
            seen[control.id] = path.name
            controls.append(control)

    if not controls:
        raise CatalogError(f"no controls found in {data_dir}")
    return controls


class Catalog:
    """Convenience wrapper holding the loaded controls with id lookup."""

    def __init__(self, controls: list[Control]):
        self.controls = controls
        self._by_id = {c.id: c for c in controls}

    @classmethod
    def load(cls, data_dir: Path | None = None) -> "Catalog":
        return cls(load_controls(data_dir))

    def get(self, control_id: str) -> Control | None:
        return self._by_id.get(control_id)

    def __len__(self) -> int:
        return len(self.controls)
