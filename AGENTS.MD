Polish the vulnerability intelligence dashboard and fix metric semantics.

Current issues observed on microsoftpatchtuesday.nl:
1. CVEs by severity total shows 1,891 while total CVEs is 1,843.
   - Fix backend aggregation to count distinct CVEs, not product mappings.
2. Top EPSS chart displays values like 337 instead of 33.7%.
   - Format EPSS as percentages consistently.
3. Average CVSS is estimated from buckets.
   - Replace with a real average CVSS calculated from CVE-level scores.
   - Prefer MSRC cvss_score; fall back to nvd_cvss_score when MSRC is null.
4. Enrichment Coverage panel is semantically incorrect.
   - EPSS coverage must be enriched EPSS CVEs / total CVEs.
   - NVD coverage must be NVD enriched CVEs / total CVEs.
   - KEV should be shown as matches/count, not coverage.
5. KEV table required_action text is too long.
   - Truncate in table and show full text on detail page or tooltip.
6. Impact distribution is dominated by Unknown.
   - Add an Impact coverage KPI: CVEs with known impact / total CVEs.

Constraints:
- Do not modify collector, enrichment worker, scheduler services, Docker Compose, Alembic migrations, or database schema.
- Backend changes are allowed only in read-only /api/v1/stats aggregation logic.
- Frontend changes are allowed for display, formatting, layout and empty states.
- Preserve existing API routes.

Validation:
- docker compose config passes.
- docker compose build backend frontend passes.
- docker compose up -d backend frontend passes.
- /api/v1/stats returns severity counts that sum to total_cves.
- Dashboard renders without runtime errors.
