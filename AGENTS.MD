Fix dashboard crash in frontend/app/page.tsx.

Current issue:
Frontend crashes with:
TypeError: Cannot read properties of undefined (reading 'length')

Cause:
page.tsx uses stats.kev_cves.length, but GET /api/v1/stats does not return kev_cves.

Required:
1. In frontend/app/page.tsx, default missing arrays to []:
   - const kevCves = stats.kev_cves ?? []
   - const topEpssCves = stats.top_epss_cves ?? []
2. Replace all stats.kev_cves usages with kevCves.
3. Replace all stats.top_epss_cves usages with topEpssCves.
4. Add empty state when kevCves.length === 0.
5. Do not change collector/enrichment/scheduler.
6. npm run build must pass.
