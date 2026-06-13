# REST API

Base path: `/api/v1`.

## Health

- `GET /health` returns service status.

## CVEs

- `GET /cves`
- `GET /cves/{cve_id}`

Supported filters: `severity`, `product`, `year`, `month`, `exploited`, and `publicly_disclosed`.

## Products

- `GET /products`
- `GET /products/{id}`

## Releases

- `GET /releases`
- `GET /releases/{release_name}`

## Admin

- `POST /admin/sync` accepts `{ "release": "2026-Jun" }` and records the requested release for sync orchestration.
