"""The FastAPI adapter — thin. Every route validates its path/query exactly as
the old monolith did, pulls the shared `UseCases` off `app.state`, calls the
matching method and returns its dict unchanged.

The routers hold no orchestration and no response shaping: that all lives in
`application.use_cases`. What stays here is strictly framework business — the
`Query`/`Path` validators (copied verbatim so the OpenAPI schema and the 422
bodies are identical), the internal-route guard middleware, and the mapping of
the application's errors back onto the status codes and detail messages the old
API returned.
"""

from __future__ import annotations

import secrets

from fastapi import APIRouter, FastAPI, Header, Path, Query, Request, Response
from fastapi.responses import JSONResponse

from ...application.use_cases import ApplicationError, UseCases
from ...config import settings
from ..persistence.postgres import ROOT_SORT_KEYS, SNI_SORT_KEYS, SORT_DIRS, SORT_KEYS
from .schemas import ClientHelloIn, IngestBatch

public_router = APIRouter(prefix="/api/v1", tags=["public"])
internal_router = APIRouter(prefix="/internal/v1", tags=["internal"])


def _uc(request: Request) -> UseCases:
    return request.app.state.use_cases


# ── public reads ─────────────────────────────────────────────────────────────


@public_router.get("/ja3/{value}", summary="Look up a fingerprint by JA3 (MD5)")
async def get_ja3(
    request: Request,
    value: str = Path(..., description="32-char JA3 MD5"),
) -> dict:
    return await _uc(request).get_ja3(value, top_snis=settings.top_snis)


@public_router.get("/ja4/{value}", summary="Look up a fingerprint by JA4")
async def get_ja4(
    request: Request,
    value: str = Path(..., description="JA4 string, a_b_c"),
) -> dict:
    return await _uc(request).get_ja4(value, top_snis=settings.top_snis)


@public_router.post("/reputation", summary="Reputation for a raw ClientHello")
async def reputation(request: Request, body: ClientHelloIn) -> dict:
    """Fingerprint a raw ClientHello with this project's own engine, then look
    the result up in the corpus.

    Unlike the /ja3 and /ja4 routes, the caller doesn't compute the fingerprint —
    it hands over the bytes and we do, so the JA3/JA4 are guaranteed to be ours.
    The probe server at probe.tls-reputation.com peeks a connecting client's
    ClientHello and posts it here, but anything can: base64 a ClientHello record
    and ask what it is and whether we've seen it.

    Always returns the computed fingerprint and whether the catalog can name the
    client. `observed` says whether this exact JA4 is in the corpus; when it is,
    `reputation` carries the full reach (domains, spread, stability). An unseen
    fingerprint is a legitimate answer, and a useful one: a stable client that
    has never appeared is itself worth a second look.
    """
    return await _uc(request).reputation(body.client_hello, top_snis=settings.top_snis)


@public_router.get(
    "/fingerprint/{value}/snis",
    summary="Page through every domain a fingerprint reached",
)
async def get_fingerprint_snis(
    request: Request,
    value: str,
    limit: int = Query(100, ge=1),
    offset: int = Query(0, ge=0),
) -> dict:
    """The full SNI list, paginated.

    The fingerprint detail response embeds only the top slice. A promiscuous
    fingerprint — the interesting kind — can reach hundreds of domains, and
    that tail is the evidence for its score, so it has to be reachable.

    Accepts either a JA3 or a JA4 in the path.
    """
    limit = min(limit, settings.max_limit)
    return await _uc(request).fingerprint_snis(value, limit, offset)


@public_router.get("/sni/{value}", summary="Which fingerprints reached this domain")
async def get_sni(
    request: Request,
    value: str,
    limit: int = Query(50, ge=1),
    offset: int = Query(0, ge=0),
) -> dict:
    limit = min(limit, settings.max_limit)
    return await _uc(request).sni(value, limit, offset)


@public_router.get("/fingerprints", summary="Browse fingerprints")
async def list_fingerprints(
    request: Request,
    sort: str = Query("observations", pattern="|".join(SORT_KEYS)),
    dir: str = Query("desc", pattern="|".join(SORT_DIRS)),
    limit: int = Query(50, ge=1),
    offset: int = Query(0, ge=0),
    alpn: str | None = Query(
        None,
        description=(
            "Filter to one exact ALPN offer list, comma-joined and IN ORDER "
            "(e.g. 'h2,http/1.1'). Order matters: 'http/1.1,h2' is a different "
            "filter and a genuine anomaly. Pass an empty value to select "
            "clients that offered no ALPN. Omit for no filter."
        ),
    ),
) -> dict:
    limit = min(limit, settings.max_limit)
    return await _uc(request).list_fingerprints(sort, dir, limit, offset, alpn)


@public_router.get("/snis", summary="Browse observed domains")
async def list_snis(
    request: Request,
    sort: str = Query("observations", pattern="|".join(SNI_SORT_KEYS)),
    dir: str = Query("desc", pattern="|".join(SORT_DIRS)),
    limit: int = Query(50, ge=1),
    offset: int = Query(0, ge=0),
    category: str | None = Query(
        None,
        pattern="^auth$",
        description=(
            "Filter to a name-based category. 'auth' narrows to auth-looking "
            "server names; crossed with sort=unique_fingerprints this is the "
            "credential-stuffing lens. A hostname heuristic, not a verdict — "
            "high precision, low recall."
        ),
    ),
) -> dict:
    """Domains, sortable by how varied the fingerprints reaching them are.

    `sort=spread` is the interesting one: it ranks domains by how evenly the
    traffic to them is split across distinct client stacks.
    """
    limit = min(limit, settings.max_limit)
    return await _uc(request).list_snis(sort, dir, limit, offset, category)


@public_router.get("/roots", summary="Browse registrable (base) domains")
async def list_roots(
    request: Request,
    response: Response,
    sort: str = Query("observations", pattern="|".join(ROOT_SORT_KEYS)),
    dir: str = Query("desc", pattern="|".join(SORT_DIRS)),
    limit: int = Query(50, ge=1),
    offset: int = Query(0, ge=0),
) -> dict:
    """Every observed SNI rolled up to its registrable domain (eTLD+1).

    Collapses subdomain sprawl -- the hundreds of per-widget *.w.hcaptcha.com
    hosts become one `hcaptcha.com` row. `hostnames` is how many distinct SNIs
    fold into each; `clients` the distinct fingerprints reaching it (few clients
    behind many observations is one operator hammering). `sort=targeting` ranks
    by observations-per-client.
    """
    # The rollup scans the observations table, so let the edge cache it briefly.
    response.headers["Cache-Control"] = "public, max-age=120"
    limit = min(limit, settings.max_limit)
    return await _uc(request).list_roots(sort, dir, limit, offset)


@public_router.get(
    "/roots/{domain}/hostnames", summary="Hostnames under a registrable domain"
)
async def list_root_hostnames(
    request: Request,
    response: Response,
    domain: str = Path(..., min_length=1, max_length=253),
    limit: int = Query(100, ge=1),
    offset: int = Query(0, ge=0),
) -> dict:
    """The individual SNIs that roll up into one registrable domain. The bare
    domain is often never observed itself — only its subdomains are — so a
    /roots row drills down through here to server names that actually exist.
    """
    response.headers["Cache-Control"] = "public, max-age=120"
    limit = min(limit, settings.max_limit)
    return await _uc(request).root_hostnames(domain, limit, offset)


@public_router.get("/search", summary="Detect input type and resolve it")
async def search(request: Request, q: str = Query(..., min_length=3)) -> dict:
    """One box for all three input kinds — the site's front door.

    Reports the detected kind even when nothing matched, so the UI can say
    "that's a valid JA4, we've just never seen it" rather than "not found".
    """
    return await _uc(request).search(q, top_snis=settings.top_snis)


@public_router.get("/alpn", summary="How the corpus splits across ALPN offers")
async def get_alpn(request: Request) -> dict:
    """ALPN distribution, keyed on the offer list IN ORDER.

    The order is never normalised, because it is the signal. A browser offers
    `h2, http/1.1` in that order; a client listing them the other way round is
    not the browser it claims to be. JA4 cannot carry this — it keeps only the
    first and last character of the FIRST protocol, so `h2` and `h2, http/1.1`
    reduce to the same two characters.

    Reported both per distinct fingerprint and per observation: the two
    disagree, and the disagreement is informative. A handful of library
    fingerprints can account for a large share of connections.
    """
    return await _uc(request).alpn()


@public_router.get("/stats", summary="Corpus size")
async def get_stats(request: Request) -> dict:
    return await _uc(request).stats()


@public_router.get(
    "/graph", summary="The whole fingerprint↔domain graph (nodes + edges)"
)
async def get_graph(request: Request) -> dict:
    """Every fingerprint and every domain as nodes, every observed (fingerprint,
    SNI) pair as an edge. Ids are prefixed `f:`/`s:` so both sides share one
    namespace; `t` is the node type, `l` the label, `d` the degree, `o` the
    observation weight. One payload the client renders with WebGL — a few MB, so
    it's meant for the graph page, not for polling.
    """
    return await _uc(request).graph()


# ── internal write ───────────────────────────────────────────────────────────


@internal_router.post("/ingest", summary="Submit a batch of ClientHellos")
async def ingest(
    request: Request,
    batch: IngestBatch,
    x_ingest_key: str | None = Header(None, alias="X-Ingest-Key"),
) -> dict:
    return await _uc(request).ingest(batch.data)


# ── wiring helpers, called by the composition root ───────────────────────────


def install_error_handlers(app: FastAPI) -> None:
    """Map the application's errors onto the status codes + detail messages the
    old routes raised via HTTPException. The body shape ({"detail": ...}) is the
    same FastAPI produces for HTTPException, so responses stay byte-identical."""

    @app.exception_handler(ApplicationError)
    async def _on_application_error(
        request: Request, exc: ApplicationError
    ) -> JSONResponse:
        return JSONResponse({"detail": exc.detail}, status_code=exc.status)


def install_internal_guard(app: FastAPI) -> None:
    """Reject unauthenticated writes before the body is read.

    The route would fail an unauthenticated caller anyway, but by then FastAPI
    has already deserialised the request body — so an unauthenticated caller
    could make the server parse a 5000-element batch before being told no.
    Checking here costs an attacker a header comparison instead.
    """

    @app.middleware("http")
    async def guard_internal_routes(request: Request, call_next):
        if request.url.path.startswith("/internal/"):
            if not settings.ingest_key:
                return JSONResponse(
                    {"detail": "ingest disabled: no key configured"}, status_code=503
                )
            if not secrets.compare_digest(
                request.headers.get("X-Ingest-Key", ""), settings.ingest_key
            ):
                return JSONResponse({"detail": "bad ingest key"}, status_code=401)
        return await call_next(request)
