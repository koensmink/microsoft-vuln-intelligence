Rebuild the frontend dashboard to match the provided dark vulnerability intelligence dashboard concept.

Scope:
- Frontend-focused implementation.
- Backend changes only allowed for /api/v1/stats aggregation fields.

Constraints:
- Do not modify MSRC collector.
- Do not modify enrichment worker.
- Do not modify scheduler services.
- Do not modify Docker Compose.
- Do not modify Alembic migrations.
- Do not modify database schema.
- Do not introduce new external APIs.
- Existing enrichment data (NVD, EPSS, KEV) must be consumed from the current backend API.
- Backend changes are only allowed for read-only /api/v1/stats aggregation support when strictly required.
- Preserve all existing API routes.

Required backend stats shape:
- total_cves
- critical_cves
- total_kev_vulnerabilities
- average_epss_score
- highest_epss_score
- epss_at_least_10_percent
- nvd_enriched_cves
- cves_by_severity
- cves_by_release
- cves_by_impact
- kev_distribution
- cvss_score_distribution
- top_epss_cves
- kev_cves
- immediate_action_count
- high_priority_count
- routine_count

Frontend requirements:
1. Create dashboard layout with:
   - top navigation bar
   - left sidebar
   - dark theme
   - responsive card grid

2. KPI cards:
   - Total CVEs
   - Critical CVEs
   - High EPSS >= 10%
   - KEV Catalog
   - Average CVSS

3. Charts:
   - Donut chart: CVEs by severity
   - Bar chart: CVSS score distribution
   - Donut chart: CVEs by impact
   - Bar chart: CVEs by release
   - Horizontal/table view: Top 10/20 CVEs by EPSS

4. Tables:
   - Top CVEs by EPSS
   - Known Exploited Vulnerabilities

5. Right-side panels:
   - Immediate Actions
   - Enrichment Coverage:
     - EPSS coverage
     - NVD coverage
     - KEV coverage

6. UX:
   - All cards must handle null/missing data.
   - No .length usage on possibly undefined arrays.
   - Use empty states.
   - Keep CVE links clickable.
   - Use consistent formatting for percentages and CVSS.

7. Validation:
   - npm run build passes.
   - docker compose build frontend passes.
   - docker compose up -d frontend passes.
   - Dashboard renders with current /api/v1/stats output.
