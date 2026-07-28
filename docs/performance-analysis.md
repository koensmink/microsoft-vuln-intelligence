# Performance analysis (2026-07-28)

## Method and baseline

Work was deliberately ordered as measurement, observability, caching, and client changes. Direct production measurements were attempted with `curl -L -sS -o /tmp/response -w ...`; the execution environment's outbound proxy rejected every request with HTTP tunnel status 403, so no production number is presented as if it were measured. A representative local SQLite dataset containing 5,850 CVEs was then used to compare an uncached and repeated `GET /api/v1/stats` request through the full FastAPI test client.

| Request | End-to-end | Server timing |
| --- | ---: | ---: |
| cold/miss | 553.21 ms | 537.38 ms |
| warm/hit 1 | 4.81 ms | 0.33 ms |
| warm/hit 2 | 4.03 ms | 0.34 ms |

The principal observed backend bottleneck is `/stats`: it executes multiple aggregates and materializes product and enrichment relationships. The homepage also requested `/stats` in both the root layout and page, while its other aggregations (`timeseries`, risk ranking, and monthly delta) were started together. The CVE route's previous implicit default serialized 100 relationship-heavy records.

## Request inventory

| Page | API requests before | Change |
| --- | --- | --- |
| Root layout | `/stats` | Shared React request memoization and 300-second fetch revalidation. |
| Homepage | `/stats`, `/stats/timeseries`, `/products/risk-ranking?limit=10`, `/products/monthly-delta?limit=10` | Layout/page `/stats` is deduplicated; calls remain concurrent and become ISR-cacheable. |
| CVE Explorer | `/cves` plus active filters | Explicit `limit=50`; search waits 300 ms and cancels its obsolete timer while the current result remains visible. |
| CVE detail | CVE detail and AI context | Intentionally unchanged and excluded from the stats cache. |
| KEV | `/cves?kev_only=true&limit=500` | Intentionally unchanged because this is a dedicated catalog view. |

## Aggregation SQL and query-plan status

The heaviest product aggregation is generated from `routes._product_rollup` and has this normalized shape:

```sql
SELECT cve_products.product_family,
       cve_products.product_category,
       cves.id,
       max(CASE WHEN cve_products.severity = 'Critical' THEN 1 ELSE 0 END),
       max(CASE WHEN cve_enrichment.kev_known_exploited IS TRUE THEN 1 ELSE 0 END),
       max(CASE WHEN cve_enrichment.epss_score >= 0.10 THEN 1 ELSE 0 END),
       max(coalesce(cve_products.cvss_base_score, cve_enrichment.cvss_score))
FROM cve_products
JOIN cves ON cves.id = cve_products.cve_id
LEFT OUTER JOIN cve_enrichment ON cves.id = cve_enrichment.cve_id
WHERE cves.id IN (<filtered CVE subquery>)
GROUP BY cve_products.product_family, cve_products.product_category, cves.id;
```

`/stats` additionally performs grouped release, severity, impact and CVSS-bucket counts plus top-EPSS and KEV queries. `/stats/timeseries` loads the latest twelve non-empty releases with CVE/product/enrichment relationships and aggregates them in Python.

`EXPLAIN (ANALYZE, BUFFERS)` could not be run responsibly: this workspace has neither a PostgreSQL service nor Docker (`docker: command not found`), and the production database is not exposed. Existing migrations already index the primary join/filter columns (`cve_id`, enrichment source, severity, exploited flags, product family/category, and release name). Therefore no speculative index or Alembic migration was added. A PostgreSQL query plan captured against production-like cardinality is required before adding an index; doing otherwise would violate the plan-based indexing requirement. Recommended follow-up commands are:

```sql
EXPLAIN (ANALYZE, BUFFERS, VERBOSE) <product rollup SQL>;
EXPLAIN (ANALYZE, BUFFERS, VERBOSE) <slowest statement logged by /stats>;
```

Record execution time, scan nodes, rows removed by filters, buffer hits/reads, and the chosen index before and after any proposed migration.
