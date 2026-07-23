# syntax=docker/dockerfile:1.7
#
# Backend: FastAPI + uvicorn, built with uv from the committed uv.lock (so the
# image is reproducible). linux/amd64, pulled by the monorepo's Ansible.

FROM python:3.13-slim AS builder

COPY --from=ghcr.io/astral-sh/uv:0.11 /uv /uvx /bin/

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never

WORKDIR /app

# Dependencies first, from the lockfile alone — this layer is cached across
# every change that doesn't touch the dependency set. --no-install-project so
# the app source isn't needed yet.
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    --mount=type=bind,source=README.md,target=README.md \
    uv sync --frozen --no-install-project --no-dev

# Then the project itself.
COPY pyproject.toml uv.lock README.md ./
COPY tlsrep ./tlsrep
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev


FROM python:3.13-slim AS runtime

# curl is here for the container healthcheck and nothing else.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin tlsrep

WORKDIR /app

COPY --from=builder /app/.venv /app/.venv
COPY --from=builder /app/tlsrep /app/tlsrep

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

USER tlsrep
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/healthz || exit 1

# The schema is applied on startup by the lifespan hook, so there is no
# separate migration step to sequence.
CMD ["uvicorn", "tlsrep.main:app", "--host", "0.0.0.0", "--port", "8000", \
     "--proxy-headers", "--forwarded-allow-ips", "*"]
