Rebuild the frontend dashboard to match the supplied dark vulnerability intelligence dashboard reference image as closely as possible.

Goal:
Move the current dashboard toward the provided target design 1:1, without changing the working data ingestion, enrichment, database schema, scheduler or Docker setup.

Target design requirements:

1. Overall layout
- Add a fixed left sidebar.
- Add a top header bar.
- Use a dark blue/black security-dashboard theme.
- Keep the layout responsive.
- Use card-based sections with subtle borders and rounded corners.

2. Sidebar navigation
Add visible navigation items:
- Overview
- CVE Explorer
- Releases
- KEV Catalog
- EPSS Insights
- Reports
- Settings

Navigation may initially link to existing or placeholder pages, but it must not break the app.

3. Top header
Show:
- Product name: Microsoft Vulnerability Intelligence
- Last updated timestamp, based on latest available release/sync data if available
- Refresh icon/button
- Time-range selector UI:
  - 7d
  - 30d
  - 90d
  - All

The time-range selector can be UI-only for now unless existing data supports filtering safely.

4. KPI cards row
Create KPI cards similar to the target design:
- Total CVEs
- Critical CVEs
- High EPSS >= 10%
- KEV Catalog
- Average CVSS

Each card should include:
- title
- main value
- short subtitle
- small visual sparkline-style accent if feasible
- hover state
- clickable navigation where meaningful:
  - Total CVEs -> /cves
  - Critical CVEs -> /cves?severity=Critical
  - High EPSS >= 10% -> /cves?min_epss=0.10
  - KEV Catalog -> /cves?kev=true
  - Average CVSS -> /cves

5. Charts
Build dashboard charts matching the design:
- CVEs by Severity donut chart
- CVSS Score Distribution bar chart
- CVEs by Impact donut chart
- CVEs by Release bar chart

Charts must use current /api/v1/stats data:
- cves_by_severity
- cvss_score_distribution
- cves_by_impact
- cves_by_release

Chart segments/bars should be clickable where practical:
- severity -> /cves?severity=<value>
- impact -> /cves?impact=<value>
- release -> /cves?release=<value>
- CVSS bucket -> /cves?cvss_bucket=<value>

If chart click handling is not feasible with the current chart library, provide clearly clickable “View details” links below each chart.

6. Tables
Add/refine these tables:
- Top CVEs by EPSS Score
- Known Exploited Vulnerabilities (KEV)

Tables must:
- preserve clickable CVE links to /cves/{cve_id}
- truncate long text such as required_action
- keep rows compact
- handle missing/null values safely

7. Right-side panels
Add panels like the reference design:
- Immediate Actions
  - Critical CVEs
  - High EPSS >= 10%
  - KEV vulnerabilities
  - CVEs without NVD data
- Enrichment Coverage
  - EPSS coverage
  - NVD coverage
  - Impact coverage
  - KEV matches

Use current stats fields:
- total_cves
- critical_cves
- epss_at_least_10_percent
- total_kev_vulnerabilities
- nvd_enriched_cves
- epss_enriched_cves
- impact_known_cves

8. Data Sources panel
Add a left-bottom data sources card showing:
- Microsoft MSRC
- NVD
- FIRST EPSS
- CISA KEV

This is a UI/status card only. Use existing available data counts to infer active/inactive state if possible.

9. CVE Explorer behavior
Update /cves to support query-parameter filters from dashboard navigation:
- severity
- impact
- release
- kev
- min_epss
- min_cvss
- cvss_bucket
- publicly_disclosed
- exploited
- priority

Apply filters client-side if the current API response provides enough data.
Only add backend filtering if strictly required and additive.

10. UX requirements
- All components must handle null or missing fields.
- Never call .length on possibly undefined arrays.
- Use default [] for optional arrays.
- Use default {} for optional objects.
- Add empty states.
- Add loading/error safe states where appropriate.
- Keep CVE links accessible.
- Add pointer cursor and hover states to clickable cards/sections.

Protected components — do not modify:
- collector/*
- collector/app/enrichment.py
- collector/enrich.py
- MSRC ingestion logic
- NVD enrichment logic
- EPSS enrichment logic
- CISA KEV enrichment logic
- scheduler services
- docker-compose.yml
- Dockerfiles
- Alembic migrations
- database schema
- database models

Backend constraints:
- Do not rename existing API fields.
- Do not remove existing API fields.
- Do not change existing API response contracts.
- Do not change existing scoring semantics.
- Prefer frontend-only implementation.
- Backend changes are allowed only if strictly required and must be additive/read-only:
  - add fields to /api/v1/stats
  - add new GET endpoints
  - add optional filters
- Existing /api/v1/stats must continue to return all current fields.

Frontend allowed changes:
- frontend/app/page.tsx
- frontend/app/cves/page.tsx
- frontend/app/layout.tsx
- frontend/app/globals.css
- frontend/src/api.ts
- new frontend components
- new frontend routes/pages if needed

Validation:
- npm run build must pass.
- docker compose config must pass.
- docker compose build frontend must pass.
- docker compose up -d frontend must pass.
- If backend was changed: docker compose build backend must pass.
- /api/v1/stats must still return valid JSON.
- /api/v1/cves must still return valid JSON.
- /cves/{cve_id} detail links must still work.
- Dashboard must render without runtime errors.

Important:
When in doubt, do not modify backend code. Prefer frontend-only changes.
