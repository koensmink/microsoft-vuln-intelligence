Implement enrichment visibility end-to-end. Do not refactor the MSRC collector and do not change scheduler services.

Current state:
- cve_enrichment table exists.
- enrichment-scheduler exists and runs python enrich.py daily.
- EPSS enrichment works.
- CISA KEV enrichment works.
- NVD is rate-limited and may remain incomplete for now.
- Frontend does not clearly show enrichment details yet.
- /api/v1/enrichment/{cve_id} currently returns 404.

Required changes:

1. Backend API
- Add or fix GET /api/v1/enrichment/{cve_id}.
- The route must accept the CVE string, e.g. CVE-2026-46306.
- Return enrichment records for that CVE from cve_enrichment.
- Ensure /api/v1/cves includes:
  - epss_score
  - epss_percentile
  - kev_known_exploited
  - kev_due_date
  - kev_vendor_project
  - kev_product
  - kev_required_action
  - nvd_cvss_score if available
  - nvd_cvss_vector if available
- Ensure /api/v1/cves/{cve_id} includes the same enrichment fields.

2. Frontend
- Show EPSS score and EPSS percentile in the vulnerabilities table.
- Show a clear KEV badge when kev_known_exploited=true.
- Show NVD CVSS only when present.
- Add enrichment details to the CVE detail page:
  - EPSS score
  - EPSS percentile
  - KEV status
  - KEV due date
  - KEV vendor/project
  - KEV product
  - KEV required action
  - NVD CVSS/vector if present
- Clearly label sources: FIRST EPSS, CISA KEV, NVD.

3. Dashboard
- Add:
  - Total KEV vulnerabilities
  - Average EPSS score
  - Top 10 CVEs by EPSS score

4. Filters
- Add filters:
  - KEV only
  - minimum EPSS score
  - minimum CVSS score if NVD data exists

5. Constraints
- Do not modify MSRC collector logic.
- Do not add a second enrichment scheduler.
- Do not make NVD required for successful enrichment.
- Do not fail the frontend when enrichment is missing.
- Preserve existing Docker Compose structure.

Validation:
- docker compose config must pass.
- docker compose up -d --build must pass.
- curl http://localhost:8000/api/v1/enrichment/CVE-2026-46306 must not return 404.
- /api/v1/cves must expose EPSS and KEV fields.
- Frontend must visibly show EPSS/KEV data.
