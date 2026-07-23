"""The reputation calculations — the heart of the corpus, framework-free.

`spread` and `stability` are the two orthogonal axes the site reads a
fingerprint by; `sni_category` is the one derived signal about a server name.
All three are pure functions of primitives, so they are trivially testable and
carry no dependency on FastAPI or the database.
"""

from __future__ import annotations

import math
import re

from .models import Stability

_STABILITY_MIN_OBSERVATIONS = 16
_RANDOMIZING_THRESHOLD = 0.5


def spread(counts: list[int]) -> float:
    """Normalised Shannon entropy of a fingerprint's SNI distribution, 0..1.

    0 means every connection went to the same domain; 1 means they were spread
    evenly across many domains. A browser sits low; a scraper pointed at target
    after target sits high. Normalising by log(n) is what makes a 5-domain and
    a 500-domain fingerprint comparable — without it the score would just
    re-measure how many domains there are. A single-domain fingerprint has no
    entropy to measure, so it scores 0.

    Reference implementation, mirrored by the SQL that materialises the column;
    the tests check the two against each other.
    """
    total = sum(counts)
    if total <= 0 or len(counts) < 2:
        return 0.0
    entropy = -sum((c / total) * math.log(c / total) for c in counts if c > 0)
    return round(entropy / math.log(len(counts)), 4)


def stability(
    *,
    observations: int,
    variants: int,
    novelty: float,
    variants_capped: bool,
    dominant: int = 0,
) -> Stability:
    """Classify how a client stack randomises its own fingerprint.

    Pure: takes the raw counts a fingerprint accumulates (observations, distinct
    JA3 variants, the novelty rate, whether the variant set is capped, and the
    dominant variant's count) and returns a Stability verdict. No IO.
    """
    observations = observations or 0
    variants = variants or 0
    novelty = float(novelty or 0.0)

    if observations < _STABILITY_MIN_OBSERVATIONS:
        klass = "unknown"
        explanation = (
            f"only {observations} observation(s) — too few to tell a permuting "
            "client from a coincidence."
        )
    elif variants <= 1:
        klass = "fixed"
        explanation = (
            f"one JA3 across {observations} connections: a deterministic stack. "
            "Libraries and command-line clients look like this."
        )
    elif novelty >= _RANDOMIZING_THRESHOLD:
        klass = "randomizing"
        explanation = (
            f"{round(novelty * 100)}% of connections presented a JA3 never seen "
            "before for this client — it reshuffles its own ClientHello. Chrome "
            "has permuted extension order since version 110."
        )
    else:
        klass = "multi_build"
        explanation = (
            f"{variants} JA3s over {observations} connections, but most repeat: "
            "a handful of stable builds sharing one JA4 rather than per-connection "
            "randomisation."
        )

    dominant_variant_share: float | None = None
    note: str | None = None
    if dominant and observations:
        share = dominant / observations
        dominant_variant_share = round(share, 4)
        # A JA4 that looks like a permuting browser, yet carries most of its
        # traffic on ONE JA3, is a deterministic client wearing that browser's
        # shape. curl-impersonate and uTLS reproduce Chrome's JA4 exactly and do
        # not implement the permutation behind it.
        if klass == "randomizing" and share >= 0.5:
            note = (
                "most traffic sits on a single JA3 despite the randomising "
                "profile — consistent with a deterministic client imitating a "
                "browser's JA4."
            )

    return Stability(
        klass=klass,
        novelty=round(novelty, 4),
        variants=variants,
        variants_capped=bool(variants_capped),
        observations=observations,
        explanation=explanation,
        dominant_variant_share=dominant_variant_share,
        note=note,
    )


# ── server-name classification ─────────────────────────────────────────────
#
# One derived signal: is this domain an authentication endpoint? The
# credential-stuffing shape is an auth endpoint reached by many distinct client
# stacks. This CLASSIFIES the name; it never EXTRACTS anything from it — pulling
# an id-looking substring out of an SNI and storing it would drag personal data
# into a corpus that refuses to keep any. High-precision, low-recall, a hint and
# never a verdict.

# Whole dot- or dash-delimited label components that mark an auth surface.
_AUTH_TERMS = (
    "login",
    "signin",
    "sign-in",
    "logon",
    "auth",
    "authn",
    "sso",
    "oauth",
    "oauth2",
    "oidc",
    "openid",
    "account",
    "accounts",
    "idp",
    "mfa",
    "otp",
    "2fa",
    "signup",
    "sign-up",
    "register",
)

# Anchored to label boundaries so `video` cannot match on "id". No nested
# quantifiers, so no ReDoS.
_AUTH_RE = re.compile(
    r"(^|[.\-])(" + "|".join(re.escape(t) for t in _AUTH_TERMS) + r")([.\-]|$)",
    re.IGNORECASE,
)

# The same, as a Postgres regex, so a WHERE filter and this label come from one
# term list rather than drifting apart. Consumed by the persistence adapter.
AUTH_SQL_REGEX = r"(^|[.\-])(" + "|".join(_AUTH_TERMS) + r")([.\-]|$)"


def sni_category(host: str | None) -> str | None:
    """Return a coarse category for a server name, or None if unclassified.

    Currently the only category is "auth". Computed on read, stored nowhere.
    """
    if not host:
        return None
    if _AUTH_RE.search(host):
        return "auth"
    return None
