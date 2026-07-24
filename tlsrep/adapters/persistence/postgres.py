"""Postgres adapter — the FingerprintRepository backed by asyncpg.

Every query the application needs lives here as a method on
`PostgresFingerprintRepository`, so the SQL surface is auditable in one file and
nothing above this boundary ever imports asyncpg. Records are converted to plain
dicts at the boundary: no `asyncpg.Record` crosses the port.
"""

from __future__ import annotations

from pathlib import Path

import asyncpg

from tlsrep.config import Settings, settings
from tlsrep.domain.reputation import AUTH_SQL_REGEX

_SCHEMA = Path(__file__).with_name("schema.sql")

# The known-variant set per fingerprint is bounded. Without a cap, a permuting
# client would write one variant row per connection — reintroducing, in a new
# table, exactly the fragmentation this schema exists to remove.
JA3_VARIANT_CAP = 128

# ── writes ──────────────────────────────────────────────────────────────────

_UPSERT_FINGERPRINT = """
INSERT INTO fingerprints (
    ja4, ja4_r, tls_version,
    alpn, ciphers, extensions, curves, sig_algs, point_formats,
    observations
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
ON CONFLICT (ja4) DO UPDATE
    SET observations = fingerprints.observations + EXCLUDED.observations,
        last_seen    = now()
RETURNING id
"""

# xmax = 0 is true only when this statement inserted the row rather than
# updating it. Deriving novelty from what the database actually did — instead
# of from a prior SELECT — is what stops two concurrent ingest workers both
# counting the same JA3 as new.
_ADD_VARIANT = """
INSERT INTO fingerprint_ja3 (fingerprint_id, ja3, ja3_raw, extensions, observations)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (fingerprint_id, ja3) DO UPDATE
    SET observations = fingerprint_ja3.observations + EXCLUDED.observations
RETURNING (xmax = 0) AS inserted
"""

_VARIANT_KNOWN = """
SELECT 1 FROM fingerprint_ja3 WHERE fingerprint_id = $1 AND ja3 = $2
"""

_VARIANT_COUNT = """
SELECT count(*) FROM fingerprint_ja3 WHERE fingerprint_id = $1
"""

# Roll the per-fingerprint variant summary back onto the parent. `ja3`/`ja3_raw`
# are set only while exactly one variant exists — a representative JA3 for a
# permuting client is a value that will never match anything again.
_SYNC_VARIANT_STATE = """
UPDATE fingerprints f
   SET ja3_variants        = v.n,
       ja3_variants_capped = (v.n >= $2),
       ja3_novel           = f.ja3_novel + $3,
       ja3                 = CASE WHEN v.n = 1 THEN v.only_ja3 ELSE NULL END,
       ja3_raw             = CASE WHEN v.n = 1 THEN v.only_raw ELSE NULL END
  FROM (
        SELECT count(*) AS n,
               min(ja3)     AS only_ja3,
               min(ja3_raw) AS only_raw
          FROM fingerprint_ja3 WHERE fingerprint_id = $1
       ) v
 WHERE f.id = $1
"""

_UPSERT_OBSERVATION = """
INSERT INTO observations (fingerprint_id, sni, count)
VALUES ($1, $2, $3)
ON CONFLICT (fingerprint_id, sni) DO UPDATE
    SET count     = observations.count + EXCLUDED.count,
        last_seen = now()
"""

# Recompute the materialised reputation metrics for the fingerprints a batch
# touched. Normalised Shannon entropy: -sum(p*ln(p)) over the SNI distribution,
# divided by ln(n) so a 5-domain and a 500-domain fingerprint stay comparable.
# Fewer than two domains has no entropy to measure and scores 0.
_REFRESH_METRICS = """
WITH d AS (
    SELECT fingerprint_id,
           count::float AS c,
           sum(count) OVER (PARTITION BY fingerprint_id)::float AS total
      FROM observations
     WHERE fingerprint_id = ANY($1::bigint[])
), e AS (
    SELECT fingerprint_id,
           count(*) AS n,
           -sum((c / total) * ln(c / total)) AS entropy
      FROM d
     WHERE c > 0 AND total > 0
     GROUP BY fingerprint_id
)
UPDATE fingerprints f
   SET unique_snis = e.n,
       spread = CASE WHEN e.n < 2 THEN 0
                     ELSE (e.entropy / ln(e.n))::real END
  FROM e
 WHERE f.id = e.fingerprint_id
"""

# The same entropy the other way round: over the distinct JA4s that reached
# each domain. Counting JA4s rather than (ja3, ja4) pairs is the whole point —
# the pair keying inflated this by two orders of magnitude wherever a permuting
# browser appeared, and pinned spread to 1.000 there.
_REFRESH_SNI_METRICS = """
WITH d AS (
    SELECT sni,
           count::float AS c,
           sum(count) OVER (PARTITION BY sni)::float AS total
      FROM observations
     WHERE sni = ANY($1::text[])
), e AS (
    SELECT sni,
           count(*) AS n,
           sum(c) AS observations,
           -sum((c / total) * ln(c / total)) AS entropy
      FROM d
     WHERE c > 0 AND total > 0
     GROUP BY sni
)
INSERT INTO snis (sni, observations, unique_fingerprints, spread)
SELECT e.sni,
       e.observations::bigint,
       e.n,
       CASE WHEN e.n < 2 THEN 0 ELSE (e.entropy / ln(e.n))::real END
  FROM e
ON CONFLICT (sni) DO UPDATE
    SET observations        = EXCLUDED.observations,
        unique_fingerprints = EXCLUDED.unique_fingerprints,
        spread              = EXCLUDED.spread,
        last_seen           = now()
"""

# ── reads ───────────────────────────────────────────────────────────────────

_FP_COLUMNS = """
    f.id, f.ja4, f.ja4_r, f.ja3, f.ja3_raw,
    f.ja3_variants, f.ja3_variants_capped, f.ja3_novel, f.ja3_novelty,
    f.tls_version, f.alpn,
    f.ciphers, f.extensions, f.curves, f.sig_algs, f.point_formats,
    f.observations, f.unique_snis, f.spread, f.first_seen, f.last_seen
"""

# Whitelist, not interpolation: `sort` reaches SQL as an ORDER BY clause, so
# it must never be caller-controlled text.
# Sort key -> the column(s) it orders by, direction applied separately. The
# direction comes from the _DIR whitelist, never interpolated raw, so the only
# interpolated ORDER BY fragments are trusted constants. `f.id ASC` is appended
# as a stable final tiebreak so paging stays deterministic under either
# direction (rows with equal sort values keep a fixed order across pages).
_DIR = {"asc": "ASC", "desc": "DESC"}
_SORT_COLS = {
    "observations": "f.observations",
    "unique_snis": "f.unique_snis",
    "spread": "f.spread",
    "last_seen": "f.last_seen",
}
SORT_KEYS = tuple(_SORT_COLS)
SORT_DIRS = tuple(_DIR)

_SNI_SORT_COLS = {
    "observations": "observations",
    "unique_fingerprints": "unique_fingerprints",
    "spread": "spread",
    "last_seen": "last_seen",
}
SNI_SORT_KEYS = tuple(_SNI_SORT_COLS)


def _fp_order(sort: str, direction: str) -> str:
    col = _SORT_COLS.get(sort, _SORT_COLS["observations"])
    return f"{col} {_DIR.get(direction, 'DESC')}, f.id ASC"


def _sni_order(sort: str, direction: str) -> str:
    # `sni` is the primary key, so it is the stable final tiebreak here.
    col = _SNI_SORT_COLS.get(sort, _SNI_SORT_COLS["observations"])
    return f"{col} {_DIR.get(direction, 'DESC')}, sni ASC"


# A ClientHello's SNI rolled up to its registrable domain (eTLD+1). A heuristic,
# not the full Public Suffix List: keep three labels when the last two look like
# a country-code second level (co.uk, com.br, ...), two otherwise. Enough to
# collapse subdomain noise -- e.g. the per-widget *.w.hcaptcha.com hosts -- into
# one row without a PSL dependency. Interpolated as a trusted constant, never
# from caller input.
_ROOT_DOMAIN_SQL = (
    "CASE WHEN sni ~ '[.](co|com|net|org|gov|edu|ac|or|ne|go|gob|mil)[.][a-z]{2}$'"
    " THEN (regexp_match(sni, '([^.]+[.][^.]+[.][a-z]{2})$'))[1]"
    " ELSE COALESCE((regexp_match(sni, '([^.]+[.][^.]+)$'))[1], sni) END"
)

_ROOT_SORT_COLS = {
    "observations": "sum(count)",
    "hostnames": "count(DISTINCT sni)",
    "clients": "count(DISTINCT fingerprint_id)",
    # obs-per-client: high means one operator hammering, low means broad traffic.
    "targeting": "sum(count)::numeric / NULLIF(count(DISTINCT fingerprint_id), 0)",
    "domain": "domain",
}
ROOT_SORT_KEYS = tuple(_ROOT_SORT_COLS)


def _root_order(sort: str, direction: str) -> str:
    # `domain` is the group key, so it is the stable final tiebreak.
    col = _ROOT_SORT_COLS.get(sort, _ROOT_SORT_COLS["observations"])
    return f"{col} {_DIR.get(direction, 'DESC')}, domain ASC"


class PostgresFingerprintRepository:
    """asyncpg-backed implementation of the `FingerprintRepository` port.

    The connection pool is an instance attribute, not a module global: the
    composition root owns one repository, and its lifecycle is `connect()` /
    `disconnect()`. Every read converts `asyncpg.Record` to a plain dict before
    returning, so nothing database-shaped crosses the port boundary.
    """

    def __init__(self, config: Settings = settings) -> None:
        self._settings = config
        self._pool: asyncpg.Pool | None = None

    def _require_pool(self) -> asyncpg.Pool:
        if self._pool is None:
            raise RuntimeError("database pool not initialised")
        return self._pool

    # ── lifecycle ──────────────────────────────────────────────────────────

    async def connect(self) -> None:
        if self._pool is None:
            self._pool = await asyncpg.create_pool(
                self._settings.dsn,
                min_size=self._settings.pool_min,
                max_size=self._settings.pool_max,
            )

    async def disconnect(self) -> None:
        if self._pool is not None:
            await self._pool.close()
            self._pool = None

    async def apply_schema(self) -> None:
        """Run schema.sql. Idempotent — every statement is IF NOT EXISTS."""
        async with self._require_pool().acquire() as conn:
            await conn.execute(_SCHEMA.read_text())

    async def healthcheck(self) -> None:
        """Raise if the store is unreachable."""
        async with self._require_pool().acquire() as conn:
            await conn.execute("SELECT 1")

    # ── writes ─────────────────────────────────────────────────────────────

    async def _record_variants(
        self, conn: asyncpg.Connection, fp_id: int, ja3s: dict
    ) -> int:
        """Record the JA3s seen for this fingerprint; return the novel connection count.

        Novel means "presented a JA3 not already in this fingerprint's known set".
        Once the set is full it is frozen, so a client that permutes its hello keeps
        missing it and stays scored as randomising however long it runs — which a
        plain variants/observations ratio would not, because that ratio decays to
        zero the moment the table saturates.
        """
        known = await conn.fetchval(_VARIANT_COUNT, fp_id)
        novel = 0

        for ja3, (ja3_raw, extensions, count) in sorted(ja3s.items()):
            if known < JA3_VARIANT_CAP:
                inserted = await conn.fetchval(
                    _ADD_VARIANT, fp_id, ja3, ja3_raw, extensions, count
                )
                if inserted:
                    known += 1
                    # Exactly ONE connection introduced this JA3, however many
                    # times the batch went on to repeat it. Counting the repeats as
                    # novel would score a client that sends the same hello a
                    # thousand times as though it had randomised a thousand times.
                    novel += 1
            elif not await conn.fetchval(_VARIANT_KNOWN, fp_id, ja3):
                # Capped: still count the novelty, just stop growing the table.
                novel += count

        return novel

    async def record_batch(self, records: list[dict]) -> int:
        """Fold a batch of parsed ClientHellos into the counters.

        Records are pre-aggregated by the caller so a batch of 500 identical hellos
        costs one UPDATE, not 500. Iteration is sorted by JA4 so concurrent workers
        touch the now-hot per-browser rows in the same order and cannot deadlock
        against one another.
        """
        written = 0
        touched: list[int] = []
        touched_snis: set[str] = set()

        async with self._require_pool().acquire() as conn, conn.transaction():
            for rec in sorted(records, key=lambda r: r["ja4"]):
                fp_id = await conn.fetchval(
                    _UPSERT_FINGERPRINT,
                    rec["ja4"],
                    rec["ja4_r"],
                    rec["tls_version"],
                    rec["alpn"],
                    rec["ciphers"],
                    # Sorted: under one JA4 the wire order varies by construction,
                    # so whichever arrived first is not "the" order.
                    sorted(rec["extensions"]),
                    rec["curves"],
                    rec["sig_algs"],
                    rec["point_formats"],
                    rec["count"],
                )
                touched.append(fp_id)

                novel = await self._record_variants(conn, fp_id, rec["ja3s"])
                await conn.execute(_SYNC_VARIANT_STATE, fp_id, JA3_VARIANT_CAP, novel)

                for sni, count in rec["snis"].items():
                    await conn.execute(_UPSERT_OBSERVATION, fp_id, sni, count)
                    touched_snis.add(sni)

                written += rec["count"]

            if touched:
                await conn.execute(_REFRESH_METRICS, sorted(touched))
            if touched_snis:
                await conn.execute(_REFRESH_SNI_METRICS, sorted(touched_snis))

        return written

    # ── reads ──────────────────────────────────────────────────────────────

    async def fingerprint_by_ja4(self, ja4: str) -> dict | None:
        async with self._require_pool().acquire() as conn:
            row = await conn.fetchrow(
                f"SELECT {_FP_COLUMNS} FROM fingerprints f WHERE f.ja4 = $1", ja4
            )
        return dict(row) if row is not None else None

    async def fingerprint_by_ja3(self, ja3: str) -> dict | None:
        """Resolve a JA3 to the fingerprint that emitted it.

        JA3 is no longer an identity: a permuting client emits a new one per
        connection, so this is a lookup through the variant table. One JA3 can in
        principle appear under more than one JA4 — two client stacks whose hellos
        differ only in something JA4 normalises away — so the busiest wins and the
        caller surfaces the ambiguity.
        """
        async with self._require_pool().acquire() as conn:
            row = await conn.fetchrow(
                f"""
                SELECT {_FP_COLUMNS}
                  FROM fingerprint_ja3 v
                  JOIN fingerprints f ON f.id = v.fingerprint_id
                 WHERE v.ja3 = $1
                 ORDER BY f.observations DESC
                 LIMIT 1
                """,
                ja3,
            )
        return dict(row) if row is not None else None

    async def ja4s_for_ja3(self, ja3: str, exclude_id: int) -> list[dict]:
        """Other fingerprints that have also emitted this JA3."""
        async with self._require_pool().acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT f.ja4, f.observations
                  FROM fingerprint_ja3 v
                  JOIN fingerprints f ON f.id = v.fingerprint_id
                 WHERE v.ja3 = $1 AND f.id <> $2
                 ORDER BY f.observations DESC
                 LIMIT 20
                """,
                ja3,
                exclude_id,
            )
        return [dict(row) for row in rows]

    async def ja3_variants(
        self, fp_id: int, limit: int, offset: int
    ) -> tuple[list[dict], int, int]:
        """The JA3s this fingerprint has emitted, busiest first.

        Returns (variants, total, dominant_count).
        """
        async with self._require_pool().acquire() as conn:
            rows = await conn.fetch(
                "SELECT ja3, ja3_raw, extensions, observations"
                "  FROM fingerprint_ja3 WHERE fingerprint_id = $1"
                " ORDER BY observations DESC, ja3 ASC LIMIT $2 OFFSET $3",
                fp_id,
                limit,
                offset,
            )
            total = await conn.fetchval(
                "SELECT count(*) FROM fingerprint_ja3 WHERE fingerprint_id = $1",
                fp_id,
            )
            # The share of connections carried by the single busiest variant. Under
            # a JA4 that otherwise looks like a permuting browser, a high value
            # means a deterministic client is wearing that browser's shape — which
            # is what curl-impersonate and uTLS do, faithfully reproducing the JA4
            # while never implementing the permutation behind it.
            dominant = await conn.fetchval(
                "SELECT max(observations) FROM fingerprint_ja3"
                " WHERE fingerprint_id = $1",
                fp_id,
            )
        return [dict(row) for row in rows], total, dominant or 0

    async def top_snis(self, fp_id: int, limit: int, offset: int = 0) -> list[dict]:
        async with self._require_pool().acquire() as conn:
            rows = await conn.fetch(
                "SELECT sni, count, first_seen, last_seen FROM observations"
                " WHERE fingerprint_id = $1"
                " ORDER BY count DESC, sni ASC LIMIT $2 OFFSET $3",
                fp_id,
                limit,
                offset,
            )
        return [dict(row) for row in rows]

    async def sni_detail(self, sni: str, limit: int, offset: int) -> dict:
        """Returns {"totals": dict|None, "rows": list[dict]}."""
        async with self._require_pool().acquire() as conn:
            totals = await conn.fetchrow(
                "SELECT observations, unique_fingerprints, spread,"
                "       first_seen, last_seen"
                " FROM snis WHERE sni = $1",
                sni,
            )
            rows = await conn.fetch(
                "SELECT f.ja3, f.ja4, f.alpn, f.observations, f.ja3_variants,"
                "       f.ja3_variants_capped, f.ja3_novelty,"
                "       o.count, o.first_seen, o.last_seen"
                " FROM observations o JOIN fingerprints f ON f.id = o.fingerprint_id"
                " WHERE o.sni = $1 ORDER BY o.count DESC LIMIT $2 OFFSET $3",
                sni,
                limit,
                offset,
            )
        return {
            "totals": dict(totals) if totals is not None else None,
            "rows": [dict(row) for row in rows],
        }

    async def list_fingerprints(
        self,
        sort: str,
        limit: int,
        offset: int,
        alpn: list[str] | None,
        direction: str,
    ) -> tuple[list[dict], int]:
        """List fingerprints, optionally filtered to one exact ALPN offer list.

        `alpn` is matched in order and as a whole, not as a set: `['h2','http/1.1']`
        and `['http/1.1','h2']` are different filters, because the offer order is
        the signal. Passing `[]` selects clients that advertised no ALPN at all.
        Passing None applies no filter.

        Returns (rows, total).
        """
        order = _fp_order(sort, direction)
        # A parameterised array equality — never string-interpolated. The ORDER BY
        # is the only interpolated fragment and it comes from the _SORT_COLS/_DIR
        # whitelists.
        # The filter sits at a different parameter index in each query, so each
        # spells its own: $3 after (limit, offset) in the page query, $1 in the
        # bare count.
        async with self._require_pool().acquire() as conn:
            if alpn is None:
                rows = await conn.fetch(
                    f"SELECT {_FP_COLUMNS} FROM fingerprints f"
                    f" ORDER BY {order} LIMIT $1 OFFSET $2",
                    limit,
                    offset,
                )
                total = await conn.fetchval("SELECT count(*) FROM fingerprints")
            else:
                rows = await conn.fetch(
                    f"SELECT {_FP_COLUMNS} FROM fingerprints f"
                    f" WHERE f.alpn = $3::text[]"
                    f" ORDER BY {order} LIMIT $1 OFFSET $2",
                    limit,
                    offset,
                    alpn,
                )
                total = await conn.fetchval(
                    "SELECT count(*) FROM fingerprints f WHERE f.alpn = $1::text[]",
                    alpn,
                )
        return [dict(row) for row in rows], total

    async def list_snis(
        self,
        sort: str,
        limit: int,
        offset: int,
        category: str | None,
        direction: str,
    ) -> tuple[list[dict], int]:
        """List domains, optionally filtered to a name-based category.

        `category="auth"` narrows to auth-looking server names. Crossed with a sort
        on unique_fingerprints or spread, that is the credential-stuffing lens: an
        auth endpoint reached by many distinct client stacks. The regex is derived
        from the same term list the Python classifier uses, so filter and label
        cannot drift apart.

        Returns (rows, total).
        """
        order = _sni_order(sort, direction)
        async with self._require_pool().acquire() as conn:
            if category == "auth":
                rows = await conn.fetch(
                    "SELECT sni, observations, unique_fingerprints, spread,"
                    "       first_seen, last_seen"
                    f" FROM snis WHERE sni ~* $3 ORDER BY {order} LIMIT $1 OFFSET $2",
                    limit,
                    offset,
                    AUTH_SQL_REGEX,
                )
                total = await conn.fetchval(
                    "SELECT count(*) FROM snis WHERE sni ~* $1", AUTH_SQL_REGEX
                )
            else:
                rows = await conn.fetch(
                    "SELECT sni, observations, unique_fingerprints, spread,"
                    "       first_seen, last_seen"
                    f" FROM snis ORDER BY {order} LIMIT $1 OFFSET $2",
                    limit,
                    offset,
                )
                total = await conn.fetchval("SELECT count(*) FROM snis")
        return [dict(row) for row in rows], total

    async def list_roots(
        self, sort: str, limit: int, offset: int, direction: str
    ) -> tuple[list[dict], int]:
        """Registrable domains: every SNI rolled up to its eTLD+1, with the
        distinct hostnames and distinct client fingerprints folded into it and
        their summed observations. `clients` is the tell — a big observation
        count behind few clients is one operator hammering, not broad traffic.

        It needs per-observation fingerprints, so this scans the observations
        table (a few hundred ms) rather than the snis summary; `total` counts the
        same roots from the small snis table. Returns (rows, total)."""
        order = _root_order(sort, direction)
        async with self._require_pool().acquire() as conn:
            rows = await conn.fetch(
                "WITH base AS ("
                f"SELECT {_ROOT_DOMAIN_SQL} AS domain, sni, fingerprint_id, count"
                " FROM observations)"
                " SELECT domain, count(DISTINCT sni) AS hostnames,"
                " count(DISTINCT fingerprint_id) AS clients,"
                " sum(count)::bigint AS observations"
                f" FROM base GROUP BY domain ORDER BY {order} LIMIT $1 OFFSET $2",
                limit,
                offset,
            )
            total = await conn.fetchval(
                f"SELECT count(DISTINCT {_ROOT_DOMAIN_SQL}) FROM snis"
            )
        return [dict(row) for row in rows], total

    async def root_hostnames(
        self, domain: str, limit: int, offset: int
    ) -> tuple[list[dict], int]:
        """The individual SNIs that roll up into one registrable domain,
        most-observed first. The bare domain is often never observed itself —
        only its subdomains are — so this is how a roots row drills down to
        pages that actually exist. Returns (rows, total)."""
        async with self._require_pool().acquire() as conn:
            rows = await conn.fetch(
                "SELECT sni, observations, unique_fingerprints"
                f" FROM snis WHERE {_ROOT_DOMAIN_SQL} = $1"
                " ORDER BY observations DESC, sni ASC LIMIT $2 OFFSET $3",
                domain,
                limit,
                offset,
            )
            total = await conn.fetchval(
                f"SELECT count(*) FROM snis WHERE {_ROOT_DOMAIN_SQL} = $1", domain
            )
        return [dict(row) for row in rows], total

    async def stats(self) -> dict:
        async with self._require_pool().acquire() as conn:
            row = await conn.fetchrow(
                "SELECT count(*) AS fingerprints,"
                "       coalesce(sum(observations), 0) AS observations,"
                "       min(first_seen) AS first_seen,"
                "       max(last_seen)  AS last_seen"
                " FROM fingerprints"
            )
            snis = await conn.fetchval("SELECT count(*) FROM snis")
        return {**dict(row), "snis": snis}

    async def alpn_distribution(self) -> list[dict]:
        """How the corpus splits across ALPN offers, in offer order.

        The order is the signal and is never normalised: a browser offers
        `h2, http/1.1` in that order, and a client that lists them the other way
        round is not the browser it claims to be. JA4 cannot express this — it
        keeps only the first and last character of the FIRST protocol, so `h2` and
        `h2, http/1.1` collapse to the same two characters.

        Three measures, and they do not mean the same thing:

          fingerprints  how many distinct client stacks offer this list
          observations  how many connections they made
          unique_snis   how many distinct domains those stacks reached

        The first two partition the corpus and sum to the whole. The third does
        NOT: a domain reached by both a browser and a library is counted under
        both, so these sum past the total. Anything rendering this has to say so
        rather than drawing it as a share of a whole.
        """
        async with self._require_pool().acquire() as conn:
            rows = await conn.fetch(
                """
                WITH per_fp AS (
                    SELECT alpn,
                           count(*)          AS fingerprints,
                           sum(observations) AS observations
                      FROM fingerprints
                     GROUP BY alpn
                ), per_sni AS (
                    SELECT f.alpn, count(DISTINCT o.sni) AS unique_snis
                      FROM fingerprints f
                      JOIN observations o ON o.fingerprint_id = f.id
                     GROUP BY f.alpn
                )
                SELECT per_fp.alpn,
                       per_fp.fingerprints,
                       per_fp.observations,
                       coalesce(per_sni.unique_snis, 0) AS unique_snis
                  FROM per_fp
                  LEFT JOIN per_sni
                         ON per_sni.alpn IS NOT DISTINCT FROM per_fp.alpn
                 ORDER BY per_fp.fingerprints DESC, per_fp.observations DESC
                """
            )
        return [dict(row) for row in rows]

    async def alpn_client_fingerprints(self) -> list[dict]:
        """Every fingerprint with its ALPN offer and weight, for the client split.

        The catalog that turns a ja4 into a client name lives in Python, not the
        database, so the join to it cannot happen in SQL. This returns the raw
        material — one row per fingerprint (ja4 is unique), carrying its ALPN offer
        and how much traffic it carries — and the router folds it into, per ALPN
        offer, how much is each known client versus still anonymous.
        """
        async with self._require_pool().acquire() as conn:
            rows = await conn.fetch(
                "SELECT alpn, ja4, observations FROM fingerprints"
            )
        return [dict(row) for row in rows]

    async def sni_count(self) -> int:
        """Distinct domains in the corpus — the denominator for per-ALPN SNI reach."""
        async with self._require_pool().acquire() as conn:
            return await conn.fetchval("SELECT count(*) FROM snis") or 0

    async def graph_data(self) -> tuple[list[dict], list[dict], list[dict]]:
        """Everything needed to draw the whole fingerprint↔domain graph in one shot:
        node metadata for both sides and the observation edges between them. Three
        plain scans — the router turns them into a nodes/edges payload.

        Returns (fingerprints, snis, edges).
        """
        async with self._require_pool().acquire() as conn:
            fps = await conn.fetch(
                "SELECT id, ja4, alpn, unique_snis, observations FROM fingerprints"
            )
            snis = await conn.fetch(
                "SELECT sni, unique_fingerprints, observations FROM snis"
            )
            edges = await conn.fetch(
                "SELECT fingerprint_id, sni, count FROM observations"
            )
        return (
            [dict(row) for row in fps],
            [dict(row) for row in snis],
            [dict(row) for row in edges],
        )
