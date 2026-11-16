"""
threatcatalog.env
=================

Minimal `.env` loader so API keys (OPENAI_API_KEY, ANTHROPIC_API_KEY, …) can live
in a git-ignored file instead of the shell. Deliberately dependency-free.

Rules:
* Looks for `.env` in the current directory, then in the project root.
* Variables already set in the environment always win; `.env` only fills gaps.
* Supports `KEY=value`, optional `export ` prefix, `#` comments, blank lines and
  single- or double-quoted values.
"""

from __future__ import annotations

import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def parse_env(text: str) -> dict[str, str]:
    """Parse `.env` text into a dict. Malformed lines are skipped."""
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        key, sep, value = line.partition("=")
        key = key.strip()
        if not sep or not key or not key.replace("_", "").isalnum():
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        elif " #" in value:
            value = value.split(" #", 1)[0].rstrip()
        out[key] = value
    return out


def load_dotenv(paths: list[Path] | None = None) -> list[str]:
    """Load the first `.env` found into ``os.environ`` without overriding
    variables that are already set. Returns the names of variables it set."""
    candidates = paths or [Path.cwd() / ".env", PROJECT_ROOT / ".env"]
    for path in candidates:
        if path.is_file():
            loaded = []
            for key, value in parse_env(path.read_text(encoding="utf-8")).items():
                if key not in os.environ:
                    os.environ[key] = value
                    loaded.append(key)
            return loaded
    return []
