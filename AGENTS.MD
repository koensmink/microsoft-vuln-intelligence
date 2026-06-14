Extend the dashboard with stronger vulnerability intelligence KPIs and charts.

Current state:
- Dashboard already shows Total CVEs, Total CISA KEV vulnerabilities, Average FIRST EPSS score and Top 10 CVEs by EPSS.
- Backend exposes CVE data, EPSS, KEV and partial NVD enrichment.
- Do not refactor collectors, enrichment worker, scheduler, database schema or Docker Compose unless strictly required for frontend/API support.

Required dashboard additions:

1. Add KPI cards:
- Critical CVEs
- Publicly disclosed CVEs
- Highest EPSS score
- CVEs with EPSS >= 1%
- CVEs with EPSS >= 10%
- NVD enriched CVEs
- CVEs with CVSS >= 9

2. Add charts using existing frontend charting approach/library:
- CVEs by severity
- CVEs by release
- CVEs by impact
- KEV vs non-KEV distribution
- CVSS score distribution
- Top 20 CVEs by EPSS score as horizontal bar chart

3. Add KEV focus table:
- Show all KEV CVEs
- Columns:
  - CVE
  - Title
  - Product
  - EPSS score
  - CVSS score
  - Severity
  - Required action
  - Due date
- CVE must link to detail page.

4. Add risk prioritization summary:
- Immediate Action count:
  KEV=true OR exploited=true OR cvss_score >= 9 OR epss_score >= 0.5
- High Priority count:
  severity=Critical OR cvss_score >= 7 OR epss_score >= 0.2
- Routine count:
  all remaining CVEs

5. Validate Average EPSS calculation:
- Average EPSS must be calculated only over CVEs with non-null EPSS.
- Display as percentage with two decimals.
- Example: epss_score=0.001 must display as 0.10%.

6. Frontend resilience:
- All charts must handle missing/null fields.
- Do not break if NVD data is incomplete.
- Show empty states where data is missing.

Validation:
- npm run build must pass.
- docker compose build frontend must pass.
- Dashboard must render with current dataset.
