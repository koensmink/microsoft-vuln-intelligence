Previous dashboard polish is incomplete.

Fix remaining metric issues:

1. CVEs by severity still sums to 1,891 while total CVEs is 1,843.
   Severity aggregation must count distinct CVEs and sum exactly to total_cves.

2. Top EPSS chart displays 337, 175, 81 etc.
   These must be formatted as percentages:
   33.7%, 17.5%, 8.1%, etc.

3. Average CVSS still says "Estimated from CVSS buckets".
   Replace with real average CVSS based on CVE-level score:
   prefer cvss_score, fallback to nvd_cvss_score.

4. Enrichment Coverage is wrong:
   - EPSS coverage = EPSS-enriched CVEs / total CVEs, expected about 99.8%.
   - NVD coverage = NVD-enriched CVEs / total CVEs, expected about 5.5%.
   - KEV should be shown as "3 known exploited", not as coverage.

Constraints:
- Do not modify collector, enrichment worker, scheduler, Docker Compose, Alembic migrations, or database schema.
- Only change read-only stats aggregation and frontend formatting.
