# Microsoft Vulnerability Intelligence Platform

Self-hosted informational platform for Microsoft vulnerability intelligence. It imports Microsoft CVRF documents from the Microsoft Security Response Center (MSRC) API, stores normalized data in PostgreSQL, and exposes it through a REST API and web UI.

The platform is informational only. It does not connect to customer environments or Microsoft tenants, perform vulnerability scanning, determine applicability automatically, or store customer data.

## Architecture

```text
frontend -> backend-api -> postgres
collector -> MSRC CVRF API -> postgres
```

Services are orchestrated with Docker Compose:

- `frontend`: Next.js web application
- `backend`: FastAPI REST API
- `collector`: independent CVRF sync process
- `postgres`: PostgreSQL 17 with persistent `postgres_data`

## Installation

Requirements:

- Docker
- Docker Compose

Clone the repository and start the stack:

```bash
docker compose up -d
```

The backend runs migrations automatically at startup. The frontend is available at <http://localhost:3000> and the API at <http://localhost:8000/api/v1>.

## Configuration

Copy `.env.example` to `.env` if you want to override defaults.

| Variable | Default | Description |
| --- | --- | --- |
| `DATABASE_URL` | `postgresql+psycopg://postgres:postgres@postgres:5432/msvi` | SQLAlchemy database URL |
| `MSRC_API_BASE_URL` | `https://api.msrc.microsoft.com/cvrf/v3.0/cvrf` | MSRC CVRF base URL |
| `RATE_LIMIT_PER_MINUTE` | `120` | API rate limit per client |
| `NEXT_PUBLIC_API_BASE_URL` | `http://localhost:8000/api/v1` | Browser-facing API base URL |

## Running the collector

Sync the current or a specific monthly release from inside the collector container:

```bash
docker compose run --rm collector python sync.py 2026-Jun
```

You can also trigger sync through the API:

```bash
curl -X POST http://localhost:8000/api/v1/admin/sync -H 'Content-Type: application/json' -d '{"release":"2026-Jun"}'
```

## API examples

```bash
curl http://localhost:8000/api/v1/health
curl http://localhost:8000/api/v1/releases/2026-Jun
curl http://localhost:8000/api/v1/cves?severity=Critical&exploited=true
curl http://localhost:8000/api/v1/cves/CVE-2026-0001
curl http://localhost:8000/api/v1/products
```

OpenAPI documentation is available at <http://localhost:8000/docs>.

## Development

Backend tests:

```bash
pytest
```

Frontend smoke tests:

```bash
cd frontend && npm test
```

## Future extension points

The collector has a source abstraction so future enrichment sources such as EPSS, CISA KEV, RSS feeds, email notifications, webhooks, and multi-user authentication can be added without reworking CVRF ingestion. These features are not implemented in the MVP.

## Running enrichment

External intelligence is collected separately from the MSRC collector so failures do not block MSRC synchronization. The enrichment worker stores source-owned data in `cve_enrichment` records and is safe to rerun:

```bash
docker compose run --rm collector python enrich.py CVE-2026-0001
```

If no CVE IDs are passed, the worker enriches every CVE already present in the database. Supported sources are NVD, CISA Known Exploited Vulnerabilities, and FIRST EPSS. Optional environment variables include `NVD_API_BASE_URL`, `NVD_API_KEY`, `KEV_CATALOG_URL`, and `EPSS_API_BASE_URL`.
