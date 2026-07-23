"""Application layer — orchestration and response shaping, framework-free.

Every method here returns the exact response dict the old FastAPI routes
returned (byte-identical field names, order and values); the HTTP adapter only
translates path/query into a call and a dict into JSON. Nothing in this module
imports FastAPI or asyncpg: it speaks to the store through the
`FingerprintRepository` port and to the domain through pure functions.

Where a route used to raise `HTTPException`, a method here raises one of the
small application errors below; the HTTP adapter maps them to the same status
codes and detail messages the old API used.
"""

from __future__ import annotations

import base64
import binascii
import logging
import re
from collections import defaultdict
from datetime import datetime

from ..domain.catalog import match_known
from ..domain.fingerprinting import fingerprint
from ..domain.fingerprinting.names import (
    CIPHERS,
    CURVES,
    EXTENSIONS,
    SIG_ALGOS,
    decorate,
)
from ..domain.reputation import sni_category, stability
from .ports import FingerprintRepository, Row

log = logging.getLogger(__name__)


# ── application errors ──────────────────────────────────────────────────────
#
# The domain and application never mention HTTP; these carry the status code and
# detail message the old routes used, and the HTTP adapter renders them.


class ApplicationError(Exception):
    """Base for expected, mapped-to-HTTP failures. Carries a status + detail."""

    status: int = 500

    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail


class BadRequest(ApplicationError):
    status = 400


class NotFound(ApplicationError):
    status = 404


class Unprocessable(ApplicationError):
    status = 422


# ── validation shapes (were inline in the old routers) ──────────────────────

_JA3_RE = re.compile(r"^[0-9a-f]{32}$", re.I)
_JA4_RE = re.compile(r"^[a-z0-9]{10}_[0-9a-f]{12}_[0-9a-f]{12}$", re.I)
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$",
    re.I,
)

_TLS_VERSION_NAMES = {
    0x0304: "TLS 1.3",
    0x0303: "TLS 1.2",
    0x0302: "TLS 1.1",
    0x0301: "TLS 1.0",
    0x0300: "SSL 3.0",
    0x0200: "SSL 2.0",
}

# A ClientHello above this is not a ClientHello. The record layer caps a single
# record at 16 KiB and reassembly of a few records covers every real client.
_MAX_HELLO_BYTES = 65536


def _iso(value: datetime | None) -> str | None:
    return value.isoformat().replace("+00:00", "Z") if value else None


class UseCases:
    """Every public read and the internal write, as framework-free methods.

    Constructed with the corpus store and the loaded known-fingerprint
    catalogue; the composition root wires both. Limit clamping and the settings
    values (top-SNI embed size, max page size) are resolved by the HTTP adapter
    and passed in, keeping this layer free of the config module too.
    """

    def __init__(self, repo: FingerprintRepository, catalogue: dict) -> None:
        self._repo = repo
        self._catalogue = catalogue

    # ── serialisation helpers (were _stability / _summary / known_client) ────

    def _known(self, ja4: str | None, alpn: list[str] | None) -> dict | None:
        """The old `known_client` shape: {name, env, label} or None."""
        hit = match_known(self._catalogue, ja4, alpn)
        if hit is None:
            return None
        return {"name": hit.name, "env": hit.env, "label": hit.label}

    def _stability(self, row: Row, dominant: int = 0) -> dict:
        """The old `_stability` dict, built from a domain `Stability`."""
        s = stability(
            observations=row["observations"],
            variants=row["ja3_variants"],
            novelty=row["ja3_novelty"],
            variants_capped=row["ja3_variants_capped"],
            dominant=dominant,
        )
        payload = {
            "class": s.klass,
            "novelty": s.novelty,
            "variants": s.variants,
            # Past the cap the variant count is a floor, not a total, and must
            # not be rendered as though it were exact.
            "variants_capped": s.variants_capped,
            "observations": s.observations,
            "explanation": s.explanation,
        }
        if s.dominant_variant_share is not None:
            payload["dominant_variant_share"] = s.dominant_variant_share
        if s.note is not None:
            payload["note"] = s.note
        return payload

    def _summary(self, row: Row) -> dict:
        """The compact shape used in list endpoints."""
        return {
            "ja4": row["ja4"],
            # Null unless exactly one JA3 has ever been seen. A representative
            # JA3 for a permuting client is a value that will never match again.
            "ja3": row["ja3"],
            "tls_version": _TLS_VERSION_NAMES.get(row["tls_version"], "unknown"),
            "alpn": list(row["alpn"]),
            "observations": row["observations"],
            "unique_snis": row["unique_snis"],
            "spread": round(row["spread"], 4),
            "stability": self._stability(row),
            # Curated label if this JA4 matches a known client build. None
            # otherwise. ALPN gates the browser cipher-list match: a Chrome
            # cipher list with a non-browser ALPN is an impersonator, not Chrome.
            "known": self._known(row["ja4"], row["alpn"]),
            "first_seen": _iso(row["first_seen"]),
            "last_seen": _iso(row["last_seen"]),
        }

    async def _detail(
        self, row: Row, top_snis: int, matched_ja3: str | None = None
    ) -> dict:
        snis = await self._repo.top_snis(row["id"], top_snis)
        embedded = 20
        variants, variant_total, dominant = await self._repo.ja3_variants(
            row["id"], embedded, 0
        )
        total = row["observations"] or 1

        payload = {
            **self._summary(row),
            "stability": self._stability(row, dominant),
            "ja3_raw": row["ja3_raw"],
            "ja4_r": row["ja4_r"],
            "cipher_suites": decorate(row["ciphers"], CIPHERS),
            # Stored sorted, and labelled as such: under one JA4 the wire order
            # varies by construction, so presenting one arrival's order as "the"
            # order would be inventing a fact.
            "extensions": decorate(row["extensions"], EXTENSIONS),
            "extensions_sorted": True,
            "curves": decorate(row["curves"], CURVES),
            "sig_algs": decorate(row["sig_algs"], SIG_ALGOS),
            "point_formats": [f"0x{v:04x}" for v in row["point_formats"]],
            "ja3_variants": {
                "total": variant_total,
                # Two different facts, deliberately separate. `capped` means
                # ingest stopped growing the stored set, so `total` is a floor.
                # `truncated` means this response carries only the busiest slice
                # of what IS stored.
                "capped": bool(row["ja3_variants_capped"]),
                "truncated": variant_total > len(variants),
                "returned": len(variants),
                "items": [
                    {
                        "ja3": v["ja3"],
                        "ja3_raw": v["ja3_raw"],
                        "observations": v["observations"],
                    }
                    for v in variants
                ],
            },
            "top_snis": [
                {
                    "sni": s["sni"],
                    "count": s["count"],
                    "share": round(s["count"] / total, 6),
                    "first_seen": _iso(s["first_seen"]),
                    "last_seen": _iso(s["last_seen"]),
                }
                for s in snis
            ],
        }

        if matched_ja3:
            others = await self._repo.ja4s_for_ja3(matched_ja3, row["id"])
            payload["matched_ja3"] = {
                "ja3": matched_ja3,
                # The JA4 this JA3 resolved to. Non-null means the resolution
                # was unambiguous and the client may treat this page as
                # canonical.
                "canonical": row["ja4"] if not others else None,
                "also_seen_under": [
                    {"ja4": o["ja4"], "observations": o["observations"]}
                    for o in others
                ],
            }

        return payload

    async def _sni_payload(self, value: str, limit: int, offset: int) -> dict | None:
        """Shared by the /sni route and /search. Returns None when unobserved."""
        result = await self._repo.sni_detail(value, limit, offset)
        totals = result["totals"]
        if totals is None or totals["unique_fingerprints"] == 0:
            return None

        observations = int(totals["observations"])
        divisor = observations or 1

        return {
            "sni": value,
            "observations": observations,
            "unique_fingerprints": totals["unique_fingerprints"],
            # A name-based hint, not a verdict. Auth-like + many distinct
            # fingerprints is the credential-stuffing shape.
            "category": sni_category(value),
            # Entropy over the fingerprints reaching this domain, not over the
            # domains a fingerprint reaches. High spread means the callers are
            # many and evenly distributed — normal for a busy site, and the
            # signature of fingerprint rotation on an endpoint that should see
            # few distinct client stacks.
            "spread": round(totals["spread"], 4),
            "first_seen": _iso(totals["first_seen"]),
            "last_seen": _iso(totals["last_seen"]),
            "top_fingerprints": [
                {
                    "ja3": r["ja3"],
                    "ja4": r["ja4"],
                    "stability": self._stability(r),
                    "known": self._known(r["ja4"], r["alpn"]),
                    "count": r["count"],
                    "share": round(r["count"] / divisor, 6),
                    "first_seen": _iso(r["first_seen"]),
                    "last_seen": _iso(r["last_seen"]),
                }
                for r in result["rows"]
            ],
        }

    # ── public reads ─────────────────────────────────────────────────────────

    async def get_ja3(self, value: str, *, top_snis: int) -> dict:
        if not _JA3_RE.match(value):
            raise BadRequest("not a JA3 hash (expected 32 hex characters)")
        row = await self._repo.fingerprint_by_ja3(value.lower())
        if row is None:
            raise NotFound(
                "JA3 not observed. Note that a client which permutes its "
                "ClientHello emits a new JA3 per connection, so an unseen JA3 "
                "does not mean the client is unknown — look it up by JA4 instead."
            )
        return await self._detail(row, top_snis, matched_ja3=value.lower())

    async def get_ja4(self, value: str, *, top_snis: int) -> dict:
        if not _JA4_RE.match(value):
            raise BadRequest("not a JA4 string (expected a_b_c)")
        row = await self._repo.fingerprint_by_ja4(value.lower())
        if row is None:
            raise NotFound("fingerprint not observed")
        return await self._detail(row, top_snis)

    async def reputation(self, client_hello: str, *, top_snis: int) -> dict:
        """Fingerprint a raw ClientHello with our own engine, then look the
        result up in the corpus. `client_hello` is base64 of the raw record."""
        try:
            raw = base64.b64decode(client_hello, validate=True)
        except (binascii.Error, ValueError):
            raise BadRequest("client_hello is not valid base64") from None

        fp = fingerprint(raw)
        if fp is None:
            raise Unprocessable(
                "not a parseable TLS ClientHello (malformed, or arrived truncated)"
            )

        row = await self._repo.fingerprint_by_ja4(fp["ja4"])
        return {
            "ja4": fp["ja4"],
            "ja3": fp["ja3"],
            "sni": fp["sni"],
            "tls_version": _TLS_VERSION_NAMES.get(fp["tls_version"], "unknown"),
            "alpn": fp["alpn"],
            # Named client build, if the ground-truth catalog recognises this
            # JA4.
            "known": self._known(fp["ja4"], fp["alpn"]),
            # Is this exact JA4 in the corpus? The signal the negative-exclusion
            # strategy leans on: a well-formed, stable fingerprint we've never
            # seen.
            "observed": row is not None,
            "reputation": (
                await self._detail(row, top_snis) if row is not None else None
            ),
        }

    async def fingerprint_snis(self, value: str, limit: int, offset: int) -> dict:
        """Page through every domain a fingerprint reached (JA3 or JA4 in path).

        `limit` arrives already clamped to the configured maximum.
        """
        if _JA3_RE.match(value):
            row = await self._repo.fingerprint_by_ja3(value.lower())
        elif _JA4_RE.match(value):
            row = await self._repo.fingerprint_by_ja4(value.lower())
        else:
            raise BadRequest("not a JA3 or JA4 fingerprint")

        if row is None:
            raise NotFound("fingerprint not observed")

        rows = await self._repo.top_snis(row["id"], limit, offset)
        divisor = row["observations"] or 1
        return {
            "ja3": row["ja3"],
            "ja4": row["ja4"],
            "total": row["unique_snis"],
            "items": [
                {
                    "sni": r["sni"],
                    "count": r["count"],
                    "share": round(r["count"] / divisor, 6),
                    "first_seen": _iso(r["first_seen"]),
                    "last_seen": _iso(r["last_seen"]),
                }
                for r in rows
            ],
        }

    async def sni(self, value: str, limit: int, offset: int) -> dict:
        if not _HOSTNAME_RE.match(value):
            raise BadRequest("not a hostname")
        payload = await self._sni_payload(value.lower(), limit, offset)
        if payload is None:
            raise NotFound("domain not observed")
        return payload

    async def list_fingerprints(
        self,
        sort: str,
        direction: str,
        limit: int,
        offset: int,
        alpn: str | None,
    ) -> dict:
        alpn_filter: list[str] | None = None
        if alpn is not None:
            # Present-but-empty ("?alpn=") selects the no-ALPN population; a
            # non-empty value is split on comma into the offer list, order kept.
            # Whitespace is stripped because the human-readable label from
            # /api/v1/alpn joins with ", " (comma-space), and that label is
            # exactly what the browse UI sends back as the filter — without the
            # strip, the " http/1.1" element would never match the stored
            # "http/1.1".
            alpn_filter = (
                [p.strip() for p in alpn.split(",") if p.strip()] if alpn else []
            )

        rows, total = await self._repo.list_fingerprints(
            sort, limit, offset, alpn_filter, direction
        )
        return {"items": [self._summary(r) for r in rows], "total": total}

    async def list_snis(
        self,
        sort: str,
        direction: str,
        limit: int,
        offset: int,
        category: str | None,
    ) -> dict:
        rows, total = await self._repo.list_snis(
            sort, limit, offset, category, direction
        )
        return {
            "items": [
                {
                    "sni": r["sni"],
                    "observations": int(r["observations"]),
                    "unique_fingerprints": r["unique_fingerprints"],
                    "spread": round(r["spread"], 4),
                    # A name-based hint, not a verdict. Auth-like plus many
                    # distinct fingerprints is the credential-stuffing shape.
                    "category": sni_category(r["sni"]),
                    "first_seen": _iso(r["first_seen"]),
                    "last_seen": _iso(r["last_seen"]),
                }
                for r in rows
            ],
            "total": total,
        }

    async def list_roots(
        self, sort: str, direction: str, limit: int, offset: int
    ) -> dict:
        rows, total = await self._repo.list_roots(sort, limit, offset, direction)
        return {
            "items": [
                {
                    "domain": r["domain"],
                    "hostnames": int(r["hostnames"]),
                    "observations": int(r["observations"]),
                }
                for r in rows
            ],
            "total": total,
        }

    async def search(self, q: str, *, top_snis: int) -> dict:
        """One box for all three input kinds — the site's front door.

        Reports the detected kind even when nothing matched, so the UI can say
        "that's a valid JA4, we've just never seen it" rather than "not found".
        """
        value = q.strip().lower()

        if _JA3_RE.match(value):
            row = await self._repo.fingerprint_by_ja3(value)
            return {
                "kind": "ja3",
                "match": await self._detail(row, top_snis, matched_ja3=value)
                if row
                else None,
            }
        if _JA4_RE.match(value):
            row = await self._repo.fingerprint_by_ja4(value)
            return {
                "kind": "ja4",
                "match": await self._detail(row, top_snis) if row else None,
            }
        if _HOSTNAME_RE.match(value):
            return {
                "kind": "sni",
                "match": await self._sni_payload(value, top_snis, 0),
            }

        return {"kind": "unknown", "match": None}

    async def alpn(self) -> dict:
        """ALPN distribution, keyed on the offer list IN ORDER."""
        rows = await self._repo.alpn_distribution()
        total_fps = sum(r["fingerprints"] for r in rows) or 1
        total_obs = sum(int(r["observations"] or 0) for r in rows) or 1
        corpus_snis = await self._repo.sni_count()

        # Per-ALPN client split. The catalog names a build, but here we care
        # only about the client, so every environment of "Python requests"
        # collapses to one segment; anything the catalog does not recognise
        # falls into a single anonymous bucket keyed on None. Built once from
        # every fingerprint, then looked up per ALPN offer.
        breakdown: dict[tuple, dict[str | None, dict[str, int]]] = defaultdict(
            lambda: defaultdict(lambda: {"fingerprints": 0, "observations": 0})
        )
        for fp in await self._repo.alpn_client_fingerprints():
            hit = match_known(self._catalogue, fp["ja4"], fp["alpn"])
            name = hit.name if hit else None
            seg = breakdown[tuple(fp["alpn"])][name]
            seg["fingerprints"] += 1
            seg["observations"] += int(fp["observations"] or 0)

        def clients_of(alpn: list) -> tuple[list[dict], int, int]:
            """One ALPN offer's split by client: named segments biggest-first,
            then the anonymous remainder. Also returns the named totals, so a
            row can state how much of itself it can put a name to."""
            buckets = breakdown.get(tuple(alpn), {})
            named = [
                {"name": n, "known": True, **w}
                for n, w in buckets.items()
                if n is not None
            ]
            named.sort(
                key=lambda s: (s["fingerprints"], s["observations"]), reverse=True
            )
            anon = buckets.get(None)
            segments = named + (
                [{"name": None, "known": False, **anon}] if anon else []
            )
            return (
                segments,
                sum(s["fingerprints"] for s in named),
                sum(s["observations"] for s in named),
            )

        items = []
        known_fps_total = known_obs_total = 0
        for r in rows:
            segments, known_fps, known_obs = clients_of(r["alpn"])
            known_fps_total += known_fps
            known_obs_total += known_obs
            obs = int(r["observations"] or 0)
            items.append(
                {
                    "alpn": list(r["alpn"]),
                    "label": ", ".join(r["alpn"]) or None,
                    "fingerprints": r["fingerprints"],
                    "observations": obs,
                    "share_of_fingerprints": round(r["fingerprints"] / total_fps, 6),
                    "share_of_observations": round(obs / total_obs, 6),
                    "unique_snis": r["unique_snis"],
                    # Of every domain in the corpus, the fraction this ALPN class
                    # was seen reaching. Overlapping by construction — see
                    # `sni_counts_overlap`.
                    "share_of_snis": round(r["unique_snis"] / (corpus_snis or 1), 6),
                    # How this ALPN offer breaks down by client, and how much of
                    # it the catalog can name at all.
                    "clients": segments,
                    "known_fingerprints": known_fps,
                    "known_observations": known_obs,
                }
            )

        return {
            "total_fingerprints": total_fps,
            "total_observations": total_obs,
            # The number of distinct domains in the whole corpus. Per-ALPN SNI
            # counts are measured against this, NOT against each other: a domain
            # reached by both a browser and a library appears under both, so the
            # per-ALPN counts sum past this total and are not a partition.
            "total_snis": corpus_snis,
            "sni_counts_overlap": True,
            # Corpus-wide, how much of it the catalog can name. Everything else
            # is a fingerprint no ground-truth run has reproduced yet.
            "known_fingerprints": known_fps_total,
            "known_observations": known_obs_total,
            "items": items,
        }

    async def stats(self) -> dict:
        row = await self._repo.stats()
        return {
            "fingerprints": row["fingerprints"],
            "snis": row["snis"],
            "observations": int(row["observations"]),
            "first_seen": _iso(row["first_seen"]),
            "last_seen": _iso(row["last_seen"]),
        }

    async def graph(self) -> dict:
        """Every fingerprint and every domain as nodes, every observed
        (fingerprint, SNI) pair as an edge."""
        fps, snis, edges = await self._repo.graph_data()
        id_to_ja4 = {r["id"]: r["ja4"] for r in fps}

        nodes = []
        for r in fps:
            alpn = list(r["alpn"]) if r["alpn"] is not None else None
            known = match_known(self._catalogue, r["ja4"], alpn)
            nodes.append(
                {
                    "id": f"f:{r['ja4']}",
                    "t": "f",
                    "l": known.name if known else r["ja4"],
                    "d": r["unique_snis"],
                    "o": r["observations"],
                }
            )
        for r in snis:
            nodes.append(
                {
                    "id": f"s:{r['sni']}",
                    "t": "s",
                    "l": r["sni"],
                    "d": r["unique_fingerprints"],
                    "o": r["observations"],
                }
            )

        graph_edges = [
            {
                "s": f"f:{id_to_ja4[e['fingerprint_id']]}",
                "t": f"s:{e['sni']}",
                "w": e["count"],
            }
            for e in edges
            if e["fingerprint_id"] in id_to_ja4
        ]

        return {"nodes": nodes, "edges": graph_edges}

    # ── internal write ───────────────────────────────────────────────────────

    def _aggregate(self, hellos: list[bytes]) -> tuple[list[dict], int]:
        """Collapse a batch into one record per distinct JA4.

        Grouping is by JA4 alone. Each record carries the JA3s it saw
        underneath it — the multiplicity the site reports as `stability`.
        """
        grouped: dict[str, dict] = {}
        skipped = 0

        for raw in hellos:
            parsed = fingerprint(raw)
            if parsed is None:
                skipped += 1
                continue

            # No SNI means no domain to attribute; the fingerprint still counts.
            sni = parsed.pop("sni", None)
            ja3 = parsed.pop("ja3")
            ja3_raw = parsed.pop("ja3_raw")
            extensions = parsed["extensions"]
            key = parsed["ja4"]

            record = grouped.get(key)
            if record is None:
                record = grouped[key] = {
                    **parsed,
                    "count": 0,
                    "snis": defaultdict(int),
                    "ja3s": {},
                }

            record["count"] += 1
            if sni:
                record["snis"][sni.lower()] += 1

            # (raw string, wire extension order, how many times seen this batch)
            seen = record["ja3s"].get(ja3)
            record["ja3s"][ja3] = (
                ja3_raw,
                extensions,
                (seen[2] if seen else 0) + 1,
            )

        return list(grouped.values()), skipped

    async def ingest(self, data: list[str]) -> dict:
        """Decode, fingerprint and fold a batch of base64 ClientHellos.

        Authorisation is enforced upstream (the HTTP adapter's internal-route
        guard) before the body is ever parsed.
        """
        decoded: list[bytes] = []
        malformed = 0
        for item in data:
            try:
                raw = base64.b64decode(item, validate=True)
            except (binascii.Error, ValueError):
                malformed += 1
                continue
            if 0 < len(raw) <= _MAX_HELLO_BYTES:
                decoded.append(raw)
            else:
                malformed += 1

        records, skipped = self._aggregate(decoded)
        written = await self._repo.record_batch(records) if records else 0

        if malformed or skipped:
            log.info(
                "ingest: %d accepted, %d malformed, %d unparseable",
                written,
                malformed,
                skipped,
            )

        return {
            "accepted": written,
            "fingerprints": len(records),
            "malformed": malformed,
            "unparseable": skipped,
        }
