"""Response shapes for the application layer.

TypedDicts, not dataclasses: the use cases build these as plain dicts (the exact
JSON the API returns), so these types document and check that shape without
changing a single byte at runtime. A field marked `NotRequired` is emitted
conditionally. `from __future__ import annotations` keeps every annotation lazy,
so the forward references and unions below cost nothing.
"""

from __future__ import annotations

from typing import NotRequired, TypedDict

# ── shared leaf shapes ──────────────────────────────────────────────────────


class KnownClient(TypedDict):
    """A curated catalogue hit for a JA4 (the old `known_client`)."""

    name: str
    env: str
    label: str


# `class` is a keyword, so this one shape needs the functional form.
StabilityView = TypedDict(
    "StabilityView",
    {
        "class": str,
        "novelty": float,
        "variants": int,
        "variants_capped": bool,
        "observations": int,
        "explanation": str,
        "dominant_variant_share": NotRequired[float],
        "note": NotRequired[str],
    },
)


# A u16 paired with its human name, as `decorate()` emits it: {"value", "name"}.
# Left as a plain str->str dict to match the domain helper's own type exactly,
# rather than couple the domain to an application shape.
Decorated = dict[str, str]


# ── fingerprints ────────────────────────────────────────────────────────────


class FingerprintSummary(TypedDict):
    ja4: str
    ja3: str | None
    tls_version: str
    alpn: list[str]
    observations: int
    unique_snis: int
    spread: float
    stability: StabilityView
    known: KnownClient | None
    first_seen: str | None
    last_seen: str | None


class Ja3Variant(TypedDict):
    ja3: str
    ja3_raw: str
    observations: int


class Ja3Variants(TypedDict):
    total: int
    capped: bool
    truncated: bool
    returned: int
    items: list[Ja3Variant]


class ReachItem(TypedDict):
    """One domain a fingerprint reached (a `top_snis` / reach row)."""

    sni: str
    count: int
    share: float
    first_seen: str | None
    last_seen: str | None


class MatchedJa3Other(TypedDict):
    ja4: str
    observations: int


class MatchedJa3(TypedDict):
    ja3: str
    canonical: str | None
    also_seen_under: list[MatchedJa3Other]


class FingerprintDetail(FingerprintSummary):
    ja3_raw: str
    ja4_r: str
    cipher_suites: list[Decorated]
    extensions: list[Decorated]
    extensions_sorted: bool
    curves: list[Decorated]
    sig_algs: list[Decorated]
    point_formats: list[str]
    ja3_variants: Ja3Variants
    top_snis: list[ReachItem]
    matched_ja3: NotRequired[MatchedJa3]


class FingerprintList(TypedDict):
    items: list[FingerprintSummary]
    total: int


class FingerprintReach(TypedDict):
    ja3: str | None
    ja4: str
    total: int
    items: list[ReachItem]


# ── domains ─────────────────────────────────────────────────────────────────


class TopFingerprint(TypedDict):
    ja3: str | None
    ja4: str
    stability: StabilityView
    known: KnownClient | None
    count: int
    share: float
    first_seen: str | None
    last_seen: str | None


class DomainDetail(TypedDict):
    sni: str
    observations: int
    unique_fingerprints: int
    category: str | None
    spread: float
    first_seen: str | None
    last_seen: str | None
    top_fingerprints: list[TopFingerprint]


class DomainSummary(TypedDict):
    sni: str
    observations: int
    unique_fingerprints: int
    spread: float
    category: str | None
    first_seen: str | None
    last_seen: str | None


class DomainList(TypedDict):
    items: list[DomainSummary]
    total: int


# ── registrable-domain rollup ───────────────────────────────────────────────


class RootRow(TypedDict):
    domain: str
    hostnames: int
    clients: int
    observations: int


class RootList(TypedDict):
    items: list[RootRow]
    total: int


class RootHostname(TypedDict):
    sni: str
    observations: int
    unique_fingerprints: int


class RootHostnameList(TypedDict):
    items: list[RootHostname]
    total: int


# ── reputation / search ─────────────────────────────────────────────────────


class ReputationResult(TypedDict):
    ja4: str
    ja3: str
    sni: str | None
    tls_version: str
    alpn: list[str]
    known: KnownClient | None
    observed: bool
    reputation: FingerprintDetail | None


class SearchResult(TypedDict):
    kind: str
    match: FingerprintDetail | DomainDetail | None


# ── ALPN distribution ───────────────────────────────────────────────────────


class ClientSegment(TypedDict):
    name: str | None
    known: bool
    fingerprints: int
    observations: int


class AlpnItem(TypedDict):
    alpn: list[str]
    label: str | None
    fingerprints: int
    observations: int
    share_of_fingerprints: float
    share_of_observations: float
    unique_snis: int
    share_of_snis: float
    clients: list[ClientSegment]
    known_fingerprints: int
    known_observations: int


class AlpnDistribution(TypedDict):
    total_fingerprints: int
    total_observations: int
    total_snis: int
    sni_counts_overlap: bool
    known_fingerprints: int
    known_observations: int
    items: list[AlpnItem]


# ── stats / graph / ingest ──────────────────────────────────────────────────


class Stats(TypedDict):
    fingerprints: int
    snis: int
    observations: int
    first_seen: str | None
    last_seen: str | None


# `t`/`l`/`d`/`o` are the terse wire keys the graph renderer expects — `l` is the
# node label. It reads as an ambiguous name to the linter, but it is the wire
# contract, not a stray local, so the lint is suppressed on that field alone.
class GraphNode(TypedDict):
    id: str
    t: str
    l: str  # noqa: E741
    d: int
    o: int


class GraphEdge(TypedDict):
    s: str
    t: str
    w: int


class Graph(TypedDict):
    nodes: list[GraphNode]
    edges: list[GraphEdge]


class IngestResult(TypedDict):
    accepted: int
    fingerprints: int
    malformed: int
    unparseable: int
