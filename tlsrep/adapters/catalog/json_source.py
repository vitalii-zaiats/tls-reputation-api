"""Catalogue adapter — loads the version-controlled known-fingerprint JSON.

The catalogue is deliberately a static, reviewed file (not a table): the labels
are editorial, and they should change by review in the repo, not by ingest.
Keys beginning with `_` are comments and are dropped.
"""

from __future__ import annotations

import json
from pathlib import Path

_PATH = Path(__file__).with_name("known_fingerprints.json")


class JsonCatalogSource:
    """Implements application.ports.CatalogSource."""

    def __init__(self, path: Path = _PATH) -> None:
        self._path = path

    def load(self) -> dict[str, dict]:
        raw = json.loads(self._path.read_text())
        return {k: v for k, v in raw.items() if not str(k).startswith("_")}
