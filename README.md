\# Automated Threat Intelligence \& Log Anomaly Engine



A containerized SIEM/SOAR pipeline built with \*\*FastAPI\*\*, \*\*Redis Streams \& Sorted Sets\*\*, \*\*PostgreSQL\*\*, and an \*\*HTMX/HTML SOC Triage Dashboard\*\*.



\## Key Features

\- \*\*Log Ingestion \& Normalization (`/ingest`):\*\* Authenticates via `X-API-Key`, enforces payload/line size limits, parses `sshd` and `nginx` logs into a normalized schema (`log\_events`), and enqueues events onto a bounded Redis Stream (`tie:events`).

\- \*\*Stateful MITRE ATT\&CK Detection (`TIE-001` – `TIE-004`):\*\*

&#x20; - `TIE-001` (`T1110.001`): Sliding-window SSH/login brute-force detection in Redis.

&#x20; - `TIE-002` (`T1110.003`): Password spraying across multiple distinct usernames.

&#x20; - `TIE-003` (`T1078`): Impossible-travel detection using Haversine distance and velocity thresholds.

&#x20; - `TIE-004` (`T1190`): Web exploit payload detection (path traversal, SQLi, XSS patterns).

\- \*\*Threat Intelligence Enrichment \& Risk Scoring:\*\* Supports offline deterministic `mock` mode out of the box plus `AbuseIPDB` lookups when `INTEL\_MODE=real`, cached in Redis with a 24-hour TTL and combined into a `0–100` risk score.

\- \*\*Alert Deduplication \& Triage UI:\*\* Uses atomic Redis `SET NX EX` cooldown keys to prevent alert fatigue while incrementing `occurrence\_count` on existing Postgres alerts, paired with a live dashboard on `http://127.0.0.1:8000/`.



\## Quick Start

1\. Copy `.env.example` to `.env` and set strong secrets for `POSTGRES\_PASSWORD`, `REDIS\_PASSWORD`, and `INGEST\_API\_KEY`.

2\. Run unit tests:

&#x20;  ```bash

&#x20;  pytest -q

