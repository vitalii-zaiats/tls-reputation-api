"""Known-fingerprint matching — the logic, not the source.

A curated map JA4 -> named client turns an anonymous JA4 into a name ("Python
requests on Alpine"). The *matching* lives here (pure); the catalogue itself is
loaded by an adapter (adapters/catalog) and passed in, so the domain never
touches the filesystem.
"""

from __future__ import annotations

from .models import Known

# The catalogue is a dict keyed by either a full JA4 (a_b_c) or a bare cipher-
# list hash (ja4_b, 12 hex). Entries are {"name", "env"?, "alpn"?}.
Catalogue = dict[str, dict]


def _alpn_ok(entry: dict, alpn: list[str] | None) -> bool:
    """Whether a bare-ja4_b entry accepts this fingerprint's ALPN.

    A browser's cipher list is that browser ONLY when the hello also offers a
    browser ALPN — impersonation tools copy Chrome's ciphers but not its ALPN.
    A browser entry carries that requirement in its own `alpn` list; an entry
    with no `alpn` matches any ALPN (right for a platform like Conscrypt).
    """
    req = entry.get("alpn")
    if req is None:
        return True
    return alpn is not None and list(alpn) in req


def match_known(
    catalogue: Catalogue, ja4: str | None, alpn: list[str] | None = None
) -> Known | None:
    """Resolve a JA4 (with ALPN gating) against the catalogue, or None.

    Two kinds of key: a full JA4 (exact — a library whose whole hello is
    stable), or a bare ja4_b (a cipher list that is a client's signature; it
    matches any JA4 with that ja4_b, since the client permutes extensions but
    not ciphers). Exact wins over bare; a bare browser entry is ALPN-gated.
    """
    if not ja4:
        return None
    entry = catalogue.get(ja4)
    if entry is None:
        parts = ja4.split("_")
        if len(parts) == 3:
            cand = catalogue.get(parts[1])
            if cand is not None and _alpn_ok(cand, alpn):
                entry = cand
    if entry is None:
        return None
    return Known(name=entry["name"], env=entry.get("env", ""))
