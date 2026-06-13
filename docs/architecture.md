# Architecture

The platform is a Docker Compose application with four services:

```text
frontend -> backend-api -> postgres
collector -> MSRC API
collector -> postgres
```

The backend owns the documented REST API, OpenAPI schema, input validation, rate limiting, structured logs, and health checks. The collector runs independently and imports monthly CVRF documents from the Microsoft Security Response Center API. PostgreSQL stores normalized releases, CVEs, products, affected products, remediations, and sync runs.

The collector writes with upserts so repeated runs preserve historical data without creating duplicate CVE or release records. The parser and sync code are intentionally separated so future enrichment sources can be added behind similar source-specific adapters.
