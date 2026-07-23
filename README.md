# tls-reputation-api

The [tls-reputation.com](https://tls-reputation.com) backend — a free, open
reputation database for TLS client fingerprints (JA3/JA4). Split out of the
monorepo. **Hexagonal architecture** (ports & adapters): the domain and
application layers are agnostic to FastAPI and to Postgres — the web framework
and the database are adapters wired in at the composition root.

## Develop

```sh
uv sync                     # create .venv, install deps + dev group
uv run uvicorn tlsrep.main:app --reload   # http://localhost:8000
uv run pytest               # tests
uv run ruff check .         # lint
```

Needs a Postgres reachable at `TLSREP_DSN` (default
`postgresql://tlsrep:tlsrep@localhost:5432/tlsrep`). Reads under `/api/v1`,
internal writes under `/internal/v1` (gated by `TLSREP_INGEST_KEY`).

## Layout

```
tlsrep/
  domain/            pure — no fastapi, no asyncpg
    fingerprinting/  TLS ClientHello parsing + JA3/JA4 (BSD-3)
    catalog.py       known-client matching (catalogue injected)
    reputation.py    spread · stability · sni_category
    models.py        domain dataclasses
  application/
    ports.py         FingerprintRepository, CatalogSource (Protocols)
    use_cases.py     lookup / list / ingest / stats / graph
  adapters/
    persistence/     asyncpg implementation of the repository port
    catalog/         loads known_fingerprints.json
    http/            FastAPI routers + pydantic schemas (thin)
  config.py          env-driven settings (read at the composition root)
  main.py            composition root: wire adapters → FastAPI app
```

The rule: `domain/` and `application/` import nothing from `fastapi`/`asyncpg`.
Swapping FastAPI for another framework is a new `adapters/http` and nothing else.

## Deploy

`uv`-based Dockerfile builds the image; CI publishes it to
`ghcr.io/vitalii-zaiats/tls-reputation-backend`. The Ansible playbook in the
monorepo deploys that image to the host (see the monorepo's `make deploy-backend`).

Licence: Apache-2.0. Corpus data: CC BY 4.0.
