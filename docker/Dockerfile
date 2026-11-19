# syntax=docker/dockerfile:1
FROM python:3.12-slim AS builder
WORKDIR /build
COPY pyproject.toml ./
RUN pip install --no-cache-dir --prefix=/install .

FROM python:3.12-slim AS runtime
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/app/src
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin tie
COPY --from=builder /install /usr/local
WORKDIR /app
COPY src ./src
COPY simulator ./simulator
USER 10001
# Command is set per-service in docker-compose.yml (api vs worker).
