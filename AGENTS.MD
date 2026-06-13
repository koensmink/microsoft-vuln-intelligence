You are working on repository: microsoft-vuln-intelligence.

Goal:
Build a Docker-based Microsoft vulnerability intelligence platform using the Microsoft MSRC CVRF API v3.0 as source of truth.

Current state:
- Docker Compose starts successfully.
- PostgreSQL starts.
- FastAPI backend starts.
- Collector can fetch MSRC CVRF data.
- Frontend can reach the backend.
- Basic CVE import works.
- Current import is incomplete and too flat.

Important finding:
MSRC includes CVEs for Microsoft-distributed components such as Azure Linux.
Example:
ProductID 21344-17084 resolves to:
"azl3 kernel 6.6.139.1-1 on Azure Linux 3.0"

Therefore:
- Do NOT exclude CVEs because they look like Linux/kernel/upstream/open-source CVEs.
- Do NOT filter based on CVE title.
- ProductID and ProductTree are the source of truth.
- Applicability/context must come from MSRC ProductTree + ProductStatuses + Threats + CVSSScoreSets + Remediations.

Primary source:
https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{release}
Example:
https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Jun

Architecture:
- PostgreSQL
- FastAPI backend
- Python collector
- Next.js frontend
- Docker Compose

Required refactor:

1. Collector

Refactor collector/app/sync.py.

Requirements:
- Fetch MSRC CVRF release documents.
- Validate HTTP status before parsing JSON.
- Validate content-type/body before parsing JSON.
- Keep imports idempotent.
- Parse localized text objects by reading their Value property.
  Example:
  {"Value": "June 2026 Security Updates"} -> "June 2026 Security Updates"

Parse:
- DocumentTitle.Value
- Vulnerability[].CVE
- Vulnerability[].Title.Value
- Vulnerability[].Notes
- Vulnerability[].ReleaseDate
- Vulnerability[].RevisionHistory
- ProductTree.FullProductName
- ProductTree.Branch recursively if needed
- ProductStatuses[].ProductID
- Threats[].ProductID
- Threats[].Type
- Threats[].Description.Value
- CVSSScoreSets[].ProductID
- CVSSScoreSets[].BaseScore
- CVSSScoreSets[].TemporalScore
- CVSSScoreSets[].Vector
- Remediations[].ProductID
- Remediations[].Type
- Remediations[].Description.Value
- Remediations[].URL
- Remediations[].SubType

ProductID resolution:
- Build a ProductID -> product metadata map from ProductTree.
- Use ProductStatuses[].ProductID to determine affected products.
- For each CVE and affected ProductID, create a product-specific vulnerability row.
- Severity, impact, CVSS and remediation are product-specific, not only CVE-specific.

Threat type handling:
- Type 0 = Impact
- Type 3 = Maximum severity
Use MSRC structure as source of truth.

Remediation type handling:
- Type 2 = KB / Security Update where available
- Type 5 = Known Issue where available
Preserve unknown remediation types rather than dropping them.

2. Database

Refactor schema if needed using Alembic.

Use normalized tables:

releases
- id
- release_name
- release_date
- revision_date
- document_title
- created_at
- updated_at

cves
- id
- cve_id
- title
- description
- release_date
- release_id
- created_at
- updated_at

products
- id
- product_id
- name
- cpe
- family
- created_at
- updated_at

cve_products
- id
- cve_id
- product_id
- status
- severity
- impact
- cvss_base_score
- cvss_temporal_score
- cvss_vector
- exploited
- publicly_disclosed
- created_at
- updated_at

remediations
- id
- cve_id
- product_id
- remediation_type
- subtype
- description
- url
- created_at
- updated_at

sync_runs
- id
- release_name
- started_at
- finished_at
- status
- records_processed
- error_message

Constraints:
- cves.cve_id unique
- products.product_id unique
- cve_products unique on cve_id + product_id
- remediations should avoid duplicates on cve_id + product_id + remediation_type + description + url

3. Backend API

Keep FastAPI.

Required endpoints:

GET /api/v1/health

GET /api/v1/cves
Support:
- pagination: limit, offset
- search by cve_id/title/product name
- filter severity
- filter product
- filter exploited
- filter publicly_disclosed
- filter release_name

GET /api/v1/cves/{cve_id}
Return:
- CVE base data
- release data
- affected products
- per-product severity/impact/CVSS
- remediations per product

GET /api/v1/releases
GET /api/v1/releases/{release_name}

GET /api/v1/products
GET /api/v1/products/{product_id}

GET /api/v1/stats
Return:
- total CVEs
- total products
- latest release
- count by severity
- exploited count
- publicly disclosed count

POST /api/v1/admin/sync
Trigger collector sync for a provided release_name.
If no release_name is provided, sync current release.

4. Frontend

Fix missing route:
- Create frontend/app/cves/page.tsx

Remove:
- All placeholder CVE links
- All hardcoded CVE references such as CVE-2026-12345
- All mock data

Navigation:
- / -> Dashboard
- /cves -> Vulnerabilities overview
- /cves/[cve_id] -> CVE detail
- /releases -> Releases
- /products -> Products

Dashboard:
- Total CVEs
- Latest release
- Critical count
- Important count
- Moderate count
- Low count
- Exploited count
- Publicly disclosed count

Vulnerabilities page:
- Table with:
  - CVE
  - title
  - release
  - affected product count
  - highest severity
  - highest CVSS
  - exploited
  - publicly disclosed
- Search input
- Filters:
  - severity
  - exploited
  - publicly disclosed
  - release
- Every CVE row links to /cves/{cve_id}

CVE detail page:
- CVE ID
- title
- description
- release
- affected products table:
  - product name
  - product_id
  - severity
  - impact
  - CVSS base score
  - CVSS vector
  - remediation / KB / URL
- Clearly show why this CVE is relevant:
  “Included because MSRC maps this CVE to the following Microsoft product/context: {product name}”

Products page:
- List ProductID, name, CPE if available, CVE count
- Link to filtered CVE list by product

5. Frontend API behavior

Use:
NEXT_PUBLIC_API_BASE_URL=http://backend:8000/api/v1 in Docker.

Do not silently swallow API errors.
Render a clear error message when API calls fail.

Use:
fetch(url, { cache: "no-store" })

6. Docker Compose

Ensure:
- backend and collector use the same DATABASE_URL
- frontend uses backend service name internally:
  http://backend:8000/api/v1
- postgres has a healthcheck
- backend waits for postgres health
- collector waits for postgres health
- collector restart policy is "no" for one-shot execution

7. Tests

Add tests for:
- ProductTree ProductID resolution
- localized Value extraction
- CVE + ProductID mapping
- Threat severity extraction
- CVSS extraction
- remediation extraction
- idempotent sync
- GET /api/v1/cves
- GET /api/v1/cves/{cve_id}
- frontend /cves route exists

8. Validation

After implementation, these must work:

docker compose down
docker compose build --no-cache
docker compose up -d

Then:

curl http://localhost:8000/api/v1/health
curl http://localhost:8000/api/v1/cves
curl http://localhost:8000/api/v1/releases
curl http://localhost:8000/api/v1/products
curl http://localhost:8000/api/v1/stats

Frontend:
http://localhost:3000
http://localhost:3000/cves
http://localhost:3000/releases
http://localhost:3000/products

Manual validation:
- /cves must not return 404.
- No hardcoded CVE-2026-12345 may remain.
- CVE detail pages must show affected Microsoft product/context.
- Azure Linux CVEs must not be excluded when ProductTree maps them to Azure Linux.
