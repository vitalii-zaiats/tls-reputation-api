"""Domain models — plain dataclasses, no framework or persistence types.

These are the shapes the domain and application layers speak in. Adapters map
them to/from wire JSON (the HTTP adapter) and rows (the persistence adapter).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Known:
    """A named client build from the ground-truth catalogue."""

    name: str
    env: str = ""

    @property
    def label(self) -> str:
        return f"{self.name} · {self.env}" if self.env else self.name


@dataclass(frozen=True)
class Stability:
    """Whether a client stack randomises its own ClientHello — the second axis
    of the site, orthogonal to spread. A claim about software, never about who
    runs it (the corpus stores no per-connection identity)."""

    # "fixed" | "randomizing" | "multi_build" | "unknown"
    klass: str
    novelty: float
    variants: int
    variants_capped: bool
    observations: int
    explanation: str
    dominant_variant_share: float | None = None
    note: str | None = None
