AGENTS.md

Project

Build a self-hosted Microsoft Vulnerability Intelligence Platform.

The application collects Microsoft CVEs from the Microsoft Security Response Center (MSRC) CVRF API and exposes the information through:

* REST API
* Web frontend
* PostgreSQL database

The platform is informational only.

The platform MUST NOT:

* Connect to customer environments
* Connect to Microsoft tenants
* Perform vulnerability scanning
* Determine applicability automatically
* Store customer data

The platform MUST:

* Present factual Microsoft vulnerability information
* Show affected products
* Show remediation information
* Show release history
* Expose all data through a documented REST API
* Run entirely in Docker

⸻

Primary Data Source

Use only the Microsoft Security Update Guide / MSRC CVRF API.

Examples:

https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Jun

Design the collector so that future enrichment sources can be added without major refactoring.

⸻

Architecture

frontend
    │
    ▼
backend-api
    │
    ▼
postgres
collector
    │
    ▼
MSRC API

Repository structure:

/
├── frontend/
├── backend/
├── collector/
├── database/
├── docker/
├── docs/
├── tests/
├── docker-compose.yml
└── AGENTS.md

⸻

Technology Stack

Backend:

* Python 3.13
* FastAPI
* SQLAlchemy
* Alembic
* Pydantic

Database:

* PostgreSQL 17

Frontend:

* Next.js
* React
* TypeScript
* Tailwind

Containerization:

* Docker
* Docker Compose

Testing:

* Pytest
* Playwright

⸻

Database Design

Create normalized tables.

releases

id
release_name
release_date
revision_date
document_title
created_at

cves

id
cve_id
title
description
severity
cvss_score
impact
publicly_disclosed
exploited
release_id
created_at
updated_at

products

id
name
family
vendor

affected_products

id
cve_id
product_id
fixed_build
kb_article
download_url

remediations

id
cve_id
remediation_type
description
url

sync_runs

id
started_at
finished_at
status
records_processed
error_message

⸻

Collector Requirements

Collector runs independently.

Responsibilities:

1. Retrieve monthly CVRF documents.
2. Parse vulnerabilities.
3. Parse affected products.
4. Parse remediations.
5. Update database.
6. Prevent duplicates.
7. Preserve historical data.

Collector must be idempotent.

Running multiple times must not create duplicate records.

Provide:

python sync.py

and

POST /api/v1/admin/sync

⸻

REST API

Expose OpenAPI documentation automatically.

Base path:

/api/v1

Endpoints:

Health

GET /health

CVEs

GET /cves
GET /cves/{cve_id}

Filtering:

?severity=
?product=
?year=
?month=
?exploited=
?publicly_disclosed=

Products

GET /products
GET /products/{id}

Releases

GET /releases
GET /releases/{release_name}

Examples:

GET /api/v1/releases/2026-Jun
GET /api/v1/cves/CVE-2026-12345

⸻

Frontend Requirements

Pages:

Dashboard

Display:

* Total CVEs
* Critical count
* Important count
* Exploited count
* Latest release

Vulnerabilities

Data table:

* CVE
* Severity
* Impact
* Release
* Exploited
* Publicly disclosed

Filters:

* Severity
* Product
* Release
* Search

Vulnerability Details

Display:

* Description
* Severity
* Impact
* CVSS
* Affected products
* KB articles
* Remediations

Releases

Monthly release overview.

Products

All affected Microsoft products.

⸻

UI Requirements

Use:

* Clean enterprise style
* Responsive layout
* Dark mode
* Search-first design

Do not use:

* Excessive animations
* Marketing language
* Decorative dashboards

Focus on information density.

⸻

Security Requirements

No authentication required in MVP.

Design API so authentication can be added later.

Implement:

* Input validation
* Rate limiting
* Structured logging
* Non-root containers
* Health endpoints

Never expose secrets in logs.

⸻

Docker Requirements

Provide:

docker compose up -d

Services:

frontend
backend
collector
postgres

Persistent storage:

postgres_data

Containers must restart automatically.

⸻

Documentation Requirements

Generate:

README.md
docs/api.md
docs/architecture.md

README must include:

* Installation
* Configuration
* Docker startup
* API examples

⸻

Testing Requirements

Minimum coverage:

Backend:

* API tests
* Database tests
* Parser tests

Frontend:

* Smoke tests

Collector:

* CVRF parsing tests

⸻

Future Extension Points

Design code to support future additions:

* EPSS
* CISA KEV
* RSS feeds
* Email notifications
* Webhooks
* Multi-user authentication

Do not implement these features now.

Only prepare extension points.

⸻

Definition of Done

Project is complete when:

* Docker compose starts successfully
* Database migrations run automatically
* Collector imports MSRC data
* REST API returns data
* Frontend displays data
* OpenAPI documentation is available
* Tests pass
* README is complete
