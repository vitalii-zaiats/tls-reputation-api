"""Composition root — the one place the layers are wired together.

Everything below the HTTP boundary is assembled here and nowhere else: the
catalogue is loaded, the Postgres repository is constructed, and the two are
handed to `UseCases`. The FastAPI app is a thin shell around that — CORS, the
internal-route guard, error mapping, the routers and a health check — and every
route reads the shared `UseCases` off `app.state`.

Public reads under /api/v1, internal writes under /internal/v1.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .adapters.catalog.json_source import JsonCatalogSource
from .adapters.http.routers import (
    install_error_handlers,
    install_internal_guard,
    internal_router,
    public_router,
)
from .adapters.persistence.postgres import PostgresFingerprintRepository
from .application.use_cases import UseCases
from .config import settings

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s"
)

DESCRIPTION = """
A free, open reputation database for TLS client fingerprints.

Look up a **JA3** or **JA4** fingerprint and see which domains it has been
observed reaching, and how often. Or go the other way: give a domain, get the
fingerprints that connect to it.

The signal is not what a fingerprint *looks* like — it's how widely it roams.
A real browser's fingerprint touches the handful of domains its human visits.
Some fingerprints reach for hundreds of unrelated domains in a row: a bank, a
sneaker drop, a social API, an airline. Nobody browses like that. The `spread`
score measures exactly that, as normalised entropy from 0 to 1.

**No key, no signup, no rate limit beyond fair use.** The data is CC BY 4.0.

### Privacy

The corpus stores a fingerprint, a domain, and a counter. It has never stored
a client IP address, so there is nothing here that links a person to a browsing
history — and no lookup that could reveal one.

### Fingerprints

JA3 (Salesforce) and JA4 (FoxIO) are both BSD-3-Clause. The rest of the JA4+
suite is under a licence restricting commercial use and is not implemented.
""".strip()


# The composition root owns the concrete adapters and the use-case object.
repo = PostgresFingerprintRepository()
catalogue = JsonCatalogSource().load()
use_cases = UseCases(repo, catalogue)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await repo.connect()
    await repo.apply_schema()
    yield
    await repo.disconnect()


app = FastAPI(
    title="tls-reputation",
    description=DESCRIPTION,
    version="0.1.0",
    license_info={"name": "Apache-2.0"},
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=False,
    allow_methods=["GET"],
    allow_headers=["*"],
)

install_internal_guard(app)
install_error_handlers(app)

app.state.use_cases = use_cases

app.include_router(public_router)
app.include_router(internal_router)


@app.get("/healthz", include_in_schema=False)
async def healthz() -> dict:
    await repo.healthcheck()
    return {"status": "ok"}
