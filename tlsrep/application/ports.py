"""Ports — the interfaces the application depends on, implemented by adapters.

Everything above this line (domain, application) is written against these
Protocols and never against a concrete FastAPI/asyncpg type. The composition
root (main.py) picks the implementations.

`Row` is a plain dict: the persistence adapter converts every asyncpg.Record to
a dict at its boundary, so no database type ever crosses this port.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

Row = dict


@runtime_checkable
class FingerprintRepository(Protocol):
    """The corpus store. One method per query the application needs; the SQL
    lives in the adapter."""

    # ── lifecycle ──
    async def connect(self) -> None: ...
    async def disconnect(self) -> None: ...
    async def apply_schema(self) -> None: ...
    async def healthcheck(self) -> None:
        """Raise if the store is unreachable (SELECT 1)."""
        ...

    # ── writes ──
    async def record_batch(self, records: list[dict]) -> int:
        """Fold parsed ClientHellos into the counters; return the count written."""
        ...

    # ── reads ──
    async def fingerprint_by_ja4(self, ja4: str) -> Row | None: ...
    async def fingerprint_by_ja3(self, ja3: str) -> Row | None: ...
    async def ja4s_for_ja3(self, ja3: str, exclude_id: int) -> list[Row]: ...

    async def ja3_variants(
        self, fp_id: int, limit: int, offset: int
    ) -> tuple[list[Row], int, int]:
        """Returns (variants, total, dominant_count)."""
        ...

    async def top_snis(self, fp_id: int, limit: int, offset: int = 0) -> list[Row]: ...
    async def sni_detail(self, sni: str, limit: int, offset: int) -> dict:
        """Returns {"totals": Row|None, "rows": list[Row]}."""
        ...

    async def list_fingerprints(
        self,
        sort: str,
        limit: int,
        offset: int,
        alpn: list[str] | None,
        direction: str,
    ) -> tuple[list[Row], int]:
        """Returns (rows, total)."""
        ...

    async def list_snis(
        self,
        sort: str,
        limit: int,
        offset: int,
        category: str | None,
        direction: str,
    ) -> tuple[list[Row], int]:
        """Returns (rows, total)."""
        ...

    async def list_roots(
        self, sort: str, limit: int, offset: int, direction: str
    ) -> tuple[list[Row], int]:
        """Every SNI rolled up to its registrable domain. Returns (rows, total)."""
        ...

    async def stats(self) -> dict: ...
    async def alpn_distribution(self) -> list[Row]: ...
    async def alpn_client_fingerprints(self) -> list[Row]: ...
    async def sni_count(self) -> int: ...

    async def graph_data(self) -> tuple[list[Row], list[Row], list[Row]]:
        """Returns (fingerprints, snis, edges)."""
        ...


@runtime_checkable
class CatalogSource(Protocol):
    """Provides the known-fingerprint catalogue as a plain dict (JA4/ja4_b -> entry)."""

    def load(self) -> dict[str, dict]: ...
