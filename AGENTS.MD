Implement enrichment visibility in backend API and frontend.

Current state:
- cve_enrichment table exists.
- EPSS enrichment is populated.
- KEV enrichment is populated.
- NVD may be unavailable due to rate limiting.
- Frontend currently does not expose enrichment information.

Tasks:

1. Backend
   - Verify Cve schema exposes:
     - epss_score
     - epss_percentile
     - kev_known_exploited
     - kev_due_date
     - kev_vendor_project
     - kev_product
     - kev_required_action
   - Ensure /api/v1/cves returns these fields.
   - Ensure /api/v1/cves/{cve_id} returns these fields.

2. Frontend
   - Add EPSS score display.
   - Add EPSS percentile display.
   - Add KEV badge:
       "Known Exploited Vulnerability"
   - Add KEV due date when available.
   - Add visual risk indicators:
       Critical
       High
       Medium
       Low

3. Dashboard
   - Add widgets:
       Total KEV vulnerabilities
       Average EPSS score
       Top 10 highest EPSS vulnerabilities

4. Search / filtering
   - Filter on:
       KEV only
       EPSS > threshold
       Critical severity

5. Do not change collector architecture.
6. Do not change scheduler services.
7. Do not modify NVD logic yet.
