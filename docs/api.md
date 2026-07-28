# Microsoft Vulnerability Intelligence API

**Versie:** `0.1.0`  
**Base path:** `/api/v1`  
**Formaat:** JSON  
**OpenAPI:** `3.1.0`

## 1. Doel

Deze API ontsluit Microsoft-kwetsbaarheidsinformatie, externe verrijkingen, productclassificatie, prioritering, release-overzichten, statistieken en AI-gegenereerde context.

## 2. Authenticatie

De lees-endpoints zijn volgens de huidige OpenAPI-specificatie niet beveiligd met een expliciet security scheme.

Voor AI-generatie wordt de volgende header gebruikt:

```http
X-AI-Admin-Key: <secret>
```

De header staat in OpenAPI als optioneel, maar de backend valideert deze sleutel.

## 3. Endpointoverzicht

| Methode | Endpoint | Doel |
|---|---|---|
| `GET` | `/api/v1/health` | Health |
| `GET` | `/api/v1/system/status` | System Status |
| `GET` | `/api/v1/system/data-quality` | System Data Quality |
| `GET` | `/api/v1/cves/prioritized` | Prioritized Cves |
| `GET` | `/api/v1/cves` | List Cves |
| `GET` | `/api/v1/enrichment/{cve_id}` | Get Enrichment |
| `GET` | `/api/v1/cves/{cve_id}` | Get Cve |
| `GET` | `/api/v1/cves/{cve_id}/ai-context` | Get Cve Ai Context |
| `POST` | `/api/v1/cves/{cve_id}/ai-context/generate` | Generate Cve Ai Context |
| `POST` | `/api/v1/ai-context/batch-generate` | Batch Generate Ai Context |
| `GET` | `/api/v1/products/summary` | Products Summary |
| `GET` | `/api/v1/products/categories` | Products Categories |
| `GET` | `/api/v1/products/risk-ranking` | Products Risk Ranking |
| `GET` | `/api/v1/products/monthly-delta` | Products Monthly Delta |
| `GET` | `/api/v1/products/mappings` | Products Mappings |
| `GET` | `/api/v1/products` | List Products |
| `GET` | `/api/v1/products/{product_id}` | Get Product |
| `GET` | `/api/v1/releases` | List Releases |
| `GET` | `/api/v1/releases/{release_name}/summary` | Release Summary |
| `GET` | `/api/v1/releases/{release_name}` | Get Release |
| `GET` | `/api/v1/stats` | Stats |
| `GET` | `/api/v1/stats/timeseries` | Stats Timeseries |
| `POST` | `/api/v1/admin/sync` | Trigger Sync |

## 4. Systeem en gezondheid

### `GET /api/v1/health`

**Doel:** Health.

**Responses**

- `200` — Successful Response

```bash
curl -sS 'http://localhost:8000/api/v1/health' | jq
```

### `GET /api/v1/system/status`

**Doel:** System Status.

**Responses**

- `200` — Successful Response; schema: `SystemStatusOut`

```bash
curl -sS 'http://localhost:8000/api/v1/system/status' | jq
```

### `GET /api/v1/system/data-quality`

**Doel:** System Data Quality.

**Responses**

- `200` — Successful Response; schema: `DataQualityOut`

```bash
curl -sS 'http://localhost:8000/api/v1/system/data-quality' | jq
```

## 5. CVE's en verrijking

### `GET /api/v1/cves/prioritized`

**Doel:** Prioritized Cves.

**Parameters**

| Naam | Locatie | Type | Verplicht | Default | Beperking |
|---|---|---|---|---|---|
| `release` | query | `string | null` | Nee |  |  |
| `priority` | query | `string | null` | Nee |  |  |
| `limit` | query | `integer` | Nee | `25` | min 1, max 100 |
| `offset` | query | `integer` | Nee | `0` | min 0 |
| `product_family` | query | `string | null` | Nee |  |  |
| `product_category` | query | `string | null` | Nee |  |  |

**Responses**

- `200` — Successful Response; schema: `array[PrioritizedCveOut]`
- `422` — Validation Error; schema: `HTTPValidationError`

```bash
curl -sS 'http://localhost:8000/api/v1/cves/prioritized' | jq
```

### `GET /api/v1/cves`

**Doel:** List Cves.

**Parameters**

| Naam | Locatie | Type | Verplicht | Default | Beperking |
|---|---|---|---|---|---|
| `limit` | query | `integer` | Nee | `100` | min 1, max 500 |
| `offset` | query | `integer` | Nee | `0` | min 0 |
| `search` | query | `string | null` | Nee |  |  |
| `severity` | query | `string | null` | Nee |  |  |
| `product` | query | `string | null` | Nee |  |  |
| `exploited` | query | `boolean | null` | Nee |  |  |
| `publicly_disclosed` | query | `boolean | null` | Nee |  |  |
| `release_name` | query | `string | null` | Nee |  |  |
| `kev_only` | query | `boolean` | Nee | `False` |  |
| `min_epss_score` | query | `number | null` | Nee |  |  |
| `min_cvss_score` | query | `number | null` | Nee |  |  |
| `impact` | query | `string | null` | Nee |  |  |
| `product_family` | query | `string | null` | Nee |  |  |
| `product_category` | query | `string | null` | Nee |  |  |

**Responses**

- `200` — Successful Response; schema: `array[CveOut]`
- `422` — Validation Error; schema: `HTTPValidationError`

```bash
curl -sS 'http://localhost:8000/api/v1/cves' | jq
```

### `GET /api/v1/cves/{cve_id}`

**Doel:** Get Cve.

**Parameters**

| Naam | Locatie | Type | Verplicht | Default | Beperking |
|---|---|---|---|---|---|
| `cve_id` | path | `string` | Ja |  |  |

**Responses**

- `200` — Successful Response; schema: `CveDetailOut`
- `422` — Validation Error; schema: `HTTPValidationError`

```bash
curl -sS 'http://localhost:8000/api/v1/cves/CVE-2026-50522' | jq
```

### `GET /api/v1/enrichment/{cve_id}`

**Doel:** Get Enrichment.

**Parameters**

| Naam | Locatie | Type | Verplicht | Default | Beperking |
|---|---|---|---|---|---|
| `cve_id` | path | `string` | Ja |  |  |

**Responses**

- `200` — Successful Response; schema: `array[CveEnrichmentOut]`
- `422` — Validation Error; schema: `HTTPValidationError`

```bash
curl -sS 'http://localhost:8000/api/v1/enrichment/CVE-2026-50522' | jq
```

## 6. AI-context

### `GET /api/v1/cves/{cve_id}/ai-context`

**Doel:** Get Cve Ai Context.

**Parameters**

| Naam | Locatie | Type | Verplicht | Default | Beperking |
|---|---|---|---|---|---|
| `cve_id` | path | `string` | Ja |  |  |

**Responses**

- `200` — Successful Response; schema: `CveAiContextOut`
- `422` — Validation Error; schema: `HTTPValidationError`

```bash
curl -sS 'http://localhost:8000/api/v1/cves/CVE-2026-50522/ai-context' | jq
```

### `POST /api/v1/cves/{cve_id}/ai-context/generate`

**Doel:** Generate Cve Ai Context.

**Parameters**

| Naam | Locatie | Type | Verplicht | Default | Beperking |
|---|---|---|---|---|---|
| `cve_id` | path | `string` | Ja |  |  |
| `force` | query | `boolean` | Nee | `False` |  |
| `X-AI-Admin-Key` | header | `string | null` | Nee |  |  |

**Responses**

- `200` — Successful Response; schema: `CveAiContextOut`
- `422` — Validation Error; schema: `HTTPValidationError`

```bash
curl -sS -X POST \
  -H "X-AI-Admin-Key: $AI_ADMIN_API_KEY" \
  'http://localhost:8000/api/v1/cves/CVE-2026-50522/ai-context/generate?force=false' | jq
```

### `POST /api/v1/ai-context/batch-generate`

**Doel:** Batch Generate Ai Context.

**Parameters**

| Naam | Locatie | Type | Verplicht | Default | Beperking |
|---|---|---|---|---|---|
| `limit` | query | `integer` | Nee | `50` | min 1, max 250 |
| `force` | query | `boolean` | Nee | `False` |  |
| `latest_only` | query | `boolean` | Nee | `True` |  |
| `X-AI-Admin-Key` | header | `string | null` | Nee |  |  |

**Responses**

- `200` — Successful Response; schema: `AiContextBatchGenerateOut`
- `422` — Validation Error; schema: `HTTPValidationError`

```bash
curl -sS -X POST \
  -H "X-AI-Admin-Key: $AI_ADMIN_API_KEY" \
  'http://localhost:8000/api/v1/ai-context/batch-generate?limit=5&force=false&latest_only=true' | jq
```

## 7. Product intelligence

### `GET /api/v1/products/summary`

**Doel:** Products Summary.

**Parameters**

| Naam | Locatie | Type | Verplicht | Default | Beperking |
|---|---|---|---|---|---|
| `release` | query | `string | null` | Nee |  |  |
| `severity` | query | `string | null` | Nee |  |  |
| `kev` | query | `boolean | null` | Nee |  |  |
| `min_epss` | query | `number | null` | Nee |  |  |
| `limit` | query | `integer` | Nee | `20` | min 1, max 100 |

**Responses**

- `200` — Successful Response; schema: `array[ProductSummaryOut]`
- `422` — Validation Error; schema: `HTTPValidationError`

```bash
curl -sS 'http://localhost:8000/api/v1/products/summary' | jq
```

### `GET /api/v1/products/categories`

**Doel:** Products Categories.

**Parameters**

| Naam | Locatie | Type | Verplicht | Default | Beperking |
|---|---|---|---|---|---|
| `release` | query | `string | null` | Nee |  |  |
| `severity` | query | `string | null` | Nee |  |  |
| `kev` | query | `boolean | null` | Nee |  |  |
| `min_epss` | query | `number | null` | Nee |  |  |
| `limit` | query | `integer` | Nee | `50` | min 1, max 100 |

**Responses**

- `200` — Successful Response; schema: `array[ProductCategoryOut]`
- `422` — Validation Error; schema: `HTTPValidationError`

```bash
curl -sS 'http://localhost:8000/api/v1/products/categories' | jq
```

### `GET /api/v1/products/risk-ranking`

**Doel:** Products Risk Ranking.

**Parameters**

| Naam | Locatie | Type | Verplicht | Default | Beperking |
|---|---|---|---|---|---|
| `limit` | query | `integer` | Nee | `10` | min 1, max 50 |

**Responses**

- `200` — Successful Response; schema: `array[ProductRiskRankingOut]`
- `422` — Validation Error; schema: `HTTPValidationError`

```bash
curl -sS 'http://localhost:8000/api/v1/products/risk-ranking' | jq
```

### `GET /api/v1/products/monthly-delta`

**Doel:** Products Monthly Delta.

**Parameters**

| Naam | Locatie | Type | Verplicht | Default | Beperking |
|---|---|---|---|---|---|
| `current_release` | query | `string | null` | Nee |  |  |
| `previous_release` | query | `string | null` | Nee |  |  |
| `limit` | query | `integer` | Nee | `10` | min 1, max 50 |

**Responses**

- `200` — Successful Response; schema: `array[ProductMonthlyDeltaOut]`
- `422` — Validation Error; schema: `HTTPValidationError`

```bash
curl -sS 'http://localhost:8000/api/v1/products/monthly-delta' | jq
```

### `GET /api/v1/products/mappings`

**Doel:** Products Mappings.

**Parameters**

| Naam | Locatie | Type | Verplicht | Default | Beperking |
|---|---|---|---|---|---|
| `limit` | query | `integer` | Nee | `500` | min 1, max 5000 |
| `offset` | query | `integer` | Nee | `0` | min 0 |

**Responses**

- `200` — Successful Response; schema: `array[ProductMappingOut]`
- `422` — Validation Error; schema: `HTTPValidationError`

```bash
curl -sS 'http://localhost:8000/api/v1/products/mappings' | jq
```

### `GET /api/v1/products`

**Doel:** List Products.

**Responses**

- `200` — Successful Response; schema: `array[ProductOut]`

```bash
curl -sS 'http://localhost:8000/api/v1/products' | jq
```

### `GET /api/v1/products/{product_id}`

**Doel:** Get Product.

**Parameters**

| Naam | Locatie | Type | Verplicht | Default | Beperking |
|---|---|---|---|---|---|
| `product_id` | path | `string` | Ja |  |  |

**Responses**

- `200` — Successful Response; schema: `ProductOut`
- `422` — Validation Error; schema: `HTTPValidationError`

```bash
curl -sS 'http://localhost:8000/api/v1/products/<product-id>' | jq
```

## 8. Releases

### `GET /api/v1/releases`

**Doel:** List Releases.

**Responses**

- `200` — Successful Response; schema: `array[ReleaseOut]`

```bash
curl -sS 'http://localhost:8000/api/v1/releases' | jq
```

### `GET /api/v1/releases/{release_name}`

**Doel:** Get Release.

**Parameters**

| Naam | Locatie | Type | Verplicht | Default | Beperking |
|---|---|---|---|---|---|
| `release_name` | path | `string` | Ja |  |  |

**Responses**

- `200` — Successful Response; schema: `ReleaseOut`
- `422` — Validation Error; schema: `HTTPValidationError`

```bash
curl -sS 'http://localhost:8000/api/v1/releases/2026-Jul' | jq
```

### `GET /api/v1/releases/{release_name}/summary`

**Doel:** Release Summary.

**Parameters**

| Naam | Locatie | Type | Verplicht | Default | Beperking |
|---|---|---|---|---|---|
| `release_name` | path | `string` | Ja |  |  |

**Responses**

- `200` — Successful Response; schema: `ReleaseSummaryOut`
- `422` — Validation Error; schema: `HTTPValidationError`

```bash
curl -sS 'http://localhost:8000/api/v1/releases/2026-Jul/summary' | jq
```

## 9. Statistieken

### `GET /api/v1/stats`

**Doel:** Stats.

**Responses**

- `200` — Successful Response; schema: `StatsOut`

```bash
curl -sS 'http://localhost:8000/api/v1/stats' | jq
```

### `GET /api/v1/stats/timeseries`

**Doel:** Stats Timeseries.

**Responses**

- `200` — Successful Response; schema: `array[StatsTimeseriesPointOut]`

```bash
curl -sS 'http://localhost:8000/api/v1/stats/timeseries' | jq
```

## 10. Beheer

### `POST /api/v1/admin/sync`

**Doel:** Trigger Sync.

**Request body:** `SyncRequest`

**Responses**

- `200` — Successful Response
- `422` — Validation Error; schema: `HTTPValidationError`

```bash
curl -sS -X POST \
  -H 'Content-Type: application/json' \
  -d '{"release_name":"2026-Jul"}' \
  'http://localhost:8000/api/v1/admin/sync' | jq
```

## 11. Belangrijkste responsemodellen

### `CveOut`

| Veld | Type | Verplicht |
|---|---|---|
| `id` | `integer` | Ja |
| `cve_id` | `string` | Ja |
| `title` | `string | null` | Nee |
| `description` | `string | null` | Nee |
| `release_date` | `string | null` | Nee |
| `severity` | `string | null` | Nee |
| `cvss_score` | `number | null` | Nee |
| `impact` | `string | null` | Nee |
| `publicly_disclosed` | `boolean` | Ja |
| `exploited` | `boolean` | Ja |
| `release` | `ReleaseOut | null` | Nee |
| `affected_product_count` | `integer | null` | Nee |
| `epss_score` | `number | null` | Nee |
| `epss_percentile` | `number | null` | Nee |
| `kev_known_exploited` | `boolean` | Nee |
| `kev_due_date` | `string | null` | Nee |
| `kev_vendor_project` | `string | null` | Nee |
| `kev_product` | `string | null` | Nee |
| `kev_required_action` | `string | null` | Nee |
| `nvd_cvss_score` | `number | null` | Nee |
| `nvd_cvss_vector` | `string | null` | Nee |

### `CveDetailOut`

| Veld | Type | Verplicht |
|---|---|---|
| `id` | `integer` | Ja |
| `cve_id` | `string` | Ja |
| `title` | `string | null` | Nee |
| `description` | `string | null` | Nee |
| `release_date` | `string | null` | Nee |
| `severity` | `string | null` | Nee |
| `cvss_score` | `number | null` | Nee |
| `impact` | `string | null` | Nee |
| `publicly_disclosed` | `boolean` | Ja |
| `exploited` | `boolean` | Ja |
| `release` | `ReleaseOut | null` | Nee |
| `affected_product_count` | `integer | null` | Nee |
| `epss_score` | `number | null` | Nee |
| `epss_percentile` | `number | null` | Nee |
| `kev_known_exploited` | `boolean` | Nee |
| `kev_due_date` | `string | null` | Nee |
| `kev_vendor_project` | `string | null` | Nee |
| `kev_product` | `string | null` | Nee |
| `kev_required_action` | `string | null` | Nee |
| `nvd_cvss_score` | `number | null` | Nee |
| `nvd_cvss_vector` | `string | null` | Nee |
| `affected_products` | `array[CveProductOut]` | Nee |
| `remediations` | `array[RemediationOut]` | Nee |
| `enrichments` | `array[CveEnrichmentOut]` | Nee |

### `PrioritizedCveOut`

| Veld | Type | Verplicht |
|---|---|---|
| `cve_id` | `string` | Ja |
| `title` | `string | null` | Nee |
| `product_family` | `string | null` | Nee |
| `product_category` | `string | null` | Nee |
| `severity` | `string` | Ja |
| `cvss_score` | `number | null` | Nee |
| `epss_score` | `number | null` | Nee |
| `nvd_status` | `string | null` | Nee |
| `kev` | `boolean` | Ja |
| `exploited` | `boolean` | Ja |
| `publicly_disclosed` | `boolean` | Ja |
| `priority_score` | `integer` | Ja |
| `priority_level` | `string` | Ja |
| `priority_reasons` | `array[string]` | Ja |

### `CveAiContextOut`

| Veld | Type | Verplicht |
|---|---|---|
| `id` | `integer` | Ja |
| `cve_id` | `integer` | Ja |
| `language` | `string` | Nee |
| `model` | `string` | Ja |
| `plain_summary` | `string` | Ja |
| `business_impact` | `string` | Ja |
| `who_should_act` | `array[string]` | Ja |
| `what_to_check` | `array[string]` | Ja |
| `recommended_action` | `string` | Ja |
| `technical_context` | `string` | Ja |
| `confidence` | `string` | Ja |
| `limitations` | `array[string]` | Ja |
| `how_to_check` | `array[string]` | Nee |
| `powershell_checks` | `array[PowerShellCheckOut]` | Nee |
| `verification_notes` | `array[string]` | Nee |
| `source_hash` | `string` | Ja |
| `created_at` | `string | null` | Nee |
| `updated_at` | `string | null` | Nee |

### `CveEnrichmentOut`

| Veld | Type | Verplicht |
|---|---|---|
| `id` | `integer` | Ja |
| `source` | `string` | Ja |
| `cvss_score` | `number | null` | Nee |
| `cvss_vector` | `string | null` | Nee |
| `severity` | `string | null` | Nee |
| `epss_score` | `number | null` | Nee |
| `epss_percentile` | `number | null` | Nee |
| `kev_known_exploited` | `boolean | null` | Nee |
| `kev_due_date` | `string | null` | Nee |
| `kev_vendor_project` | `string | null` | Nee |
| `kev_product` | `string | null` | Nee |
| `kev_required_action` | `string | null` | Nee |
| `kev_notes` | `string | null` | Nee |
| `fetched_at` | `string | null` | Nee |

### `ProductSummaryOut`

| Veld | Type | Verplicht |
|---|---|---|
| `product_family` | `string` | Ja |
| `product_category` | `string` | Ja |
| `cve_count` | `integer` | Ja |
| `critical_count` | `integer` | Nee |
| `kev_count` | `integer` | Nee |
| `high_epss_count` | `integer` | Nee |
| `average_cvss_score` | `number | null` | Nee |

### `ProductRiskRankingOut`

| Veld | Type | Verplicht |
|---|---|---|
| `product_family` | `string` | Ja |
| `product_category` | `string` | Ja |
| `cve_count` | `integer` | Ja |
| `critical_count` | `integer` | Nee |
| `kev_count` | `integer` | Nee |
| `high_epss_count` | `integer` | Nee |
| `average_cvss_score` | `number` | Nee |
| `risk_score` | `number` | Ja |
| `risk_level` | `string` | Ja |

### `ReleaseSummaryOut`

| Veld | Type | Verplicht |
|---|---|---|
| `release` | `string` | Ja |
| `release_date` | `string | string | null` | Nee |
| `total_cves` | `integer` | Ja |
| `critical_cves` | `integer` | Ja |
| `exploited_cves` | `integer` | Ja |
| `publicly_disclosed_cves` | `integer` | Ja |
| `kev_cves` | `integer` | Ja |
| `high_epss_cves` | `integer` | Ja |
| `average_cvss_score` | `number | null` | Nee |
| `highest_cvss_score` | `number | null` | Nee |
| `highest_epss_score` | `number | null` | Nee |
| `affected_product_families` | `integer` | Ja |
| `previous_release` | `string | null` | Nee |
| `cve_delta` | `integer | null` | Nee |
| `critical_delta` | `integer | null` | Nee |
| `priority_cves` | `array[PrioritizedCveOut]` | Ja |

### `StatsOut`

| Veld | Type | Verplicht |
|---|---|---|
| `total_cves` | `integer` | Ja |
| `total_products` | `integer` | Ja |
| `latest_release` | `string | null` | Ja |
| `count_by_severity` | `object` | Ja |
| `exploited_count` | `integer` | Ja |
| `publicly_disclosed_count` | `integer` | Ja |
| `total_kev_vulnerabilities` | `integer` | Ja |
| `average_epss_score` | `number | null` | Nee |
| `average_cvss_score` | `number | null` | Nee |
| `top_epss_cves` | `array[TopEpssCveOut]` | Nee |
| `critical_cves` | `integer` | Nee |
| `highest_epss_score` | `number | null` | Nee |
| `epss_enriched_cves` | `integer` | Nee |
| `epss_at_least_1_percent` | `integer` | Nee |
| `epss_at_least_10_percent` | `integer` | Nee |
| `nvd_enriched_cves` | `integer` | Nee |
| `impact_known_cves` | `integer` | Nee |
| `cvss_at_least_9` | `integer` | Nee |
| `immediate_action_count` | `integer` | Nee |
| `high_priority_count` | `integer` | Nee |
| `routine_count` | `integer` | Nee |
| `cves_by_severity` | `array[CountBucketOut]` | Nee |
| `cves_by_release` | `array[CountBucketOut]` | Nee |
| `cves_by_impact` | `array[CountBucketOut]` | Nee |
| `kev_distribution` | `array[CountBucketOut]` | Nee |
| `cvss_score_distribution` | `array[CountBucketOut]` | Nee |
| `kev_cves` | `array[KevCveOut]` | Nee |
| `top_product_families` | `array[ProductSummaryOut]` | Nee |
| `top_product_categories` | `array[ProductCategoryOut]` | Nee |

### `SystemStatusOut`

| Veld | Type | Verplicht |
|---|---|---|
| `status` | `string` | Ja |
| `database` | `string` | Ja |
| `latest_release` | `string | null` | Nee |
| `latest_release_date` | `string | string | null` | Nee |
| `last_successful_sync` | `string | null` | Nee |
| `last_sync_status` | `string | null` | Nee |
| `records_processed` | `integer | null` | Nee |
| `data_freshness_hours` | `number | null` | Nee |

### `DataQualityOut`

| Veld | Type | Verplicht |
|---|---|---|
| `total_cves` | `integer` | Ja |
| `epss_coverage` | `CoverageOut` | Ja |
| `nvd_coverage` | `CoverageOut` | Ja |
| `nvd_record_coverage` | `CoverageOut` | Ja |
| `nvd_cvss_coverage` | `CoverageOut` | Ja |
| `nvd_without_cvss` | `NvdWithoutCvssOut` | Ja |
| `ai_context_coverage` | `CoverageOut` | Ja |
| `product_classification` | `CoverageOut` | Ja |

### `AiContextBatchGenerateOut`

| Veld | Type | Verplicht |
|---|---|---|
| `selected` | `integer` | Ja |
| `generated` | `integer` | Ja |
| `skipped` | `integer` | Ja |
| `failed` | `integer` | Ja |
| `failures` | `array[AiContextBatchFailureOut]` | Nee |

## 12. AI-context

AI-context wordt in het Nederlands gegenereerd en bevat een samenvatting, bedrijfsimpact, betrokken rollen, controlepunten, aanbevolen acties, technische context, beperkingen, verificatiestappen en PowerShell-checks.

- `confidence`: betrouwbaarheidsindicatie van de AI-output.
- `limitations`: expliciete beperkingen van de brondata.
- `source_hash`: hash van de bronpayload voor caching en hergeneratie.
- `powershell_checks[].applies_to`: lijst van producten waarop een controle van toepassing is.

AI-output is interpretatieve verrijking. Microsoft-, NVD-, EPSS- en KEV-bronvelden blijven leidend voor patchbesluiten, operationele wijzigingen en incidentrespons.

## 13. Terminologie

| Term | Betekenis |
|---|---|
| MSRC | Microsoft Security Response Center brondata en releases. |
| NVD | NVD CVSS-score, vector en statusinformatie. |
| EPSS | Kansinschatting op exploitatie. |
| KEV | CISA Known Exploited Vulnerabilities-status, deadline en vereiste actie. |
| Product family | Genormaliseerde productfamilie. |
| Product category | Functionele of technische productcategorie. |
| Priority level | Afgeleide klasse `immediate`, `high` of `routine`. |

## 14. Foutafhandeling

- `403`: ongeldige AI-adminsleutel.
- `404`: object of AI-context bestaat niet.
- `422`: ongeldige invoer.
- `502`: AI-provider- of validatiefout.
- `503`: vereiste AI-configuratie ontbreekt.
- `500`: onverwachte serverfout.

De OpenAPI-specificatie documenteert standaard vooral `200` en `422`; aanvullende foutcodes volgen uit de backendlogica.

## 15. Pagination en limieten

- `GET /cves`: maximaal 500 records per request.
- `GET /cves/prioritized`: maximaal 100 records per request.
- `GET /products/mappings`: maximaal 5000 records per request.
- `POST /ai-context/batch-generate`: maximaal 250 CVE's per batch.
- Gebruik `offset` waar beschikbaar.

## 16. Operationele aanbevelingen

- Start AI-batches klein, bijvoorbeeld met `limit=5`.
- Gebruik normaal `force=false` om onnodige OpenAI-calls te voorkomen.
- Gebruik `force=true` alleen voor bewuste hergeneratie.
- Controleer `failed` en `failures` in batchresponses.
- Gebruik `/system/status` voor gezondheid en synchronisatiestatus.
- Gebruik `/system/data-quality` voor coverage van NVD, EPSS, AI-context en productclassificatie.
- Publiceer `X-AI-Admin-Key` nooit in frontendcode of openbare documentatie.

## 17. Interactieve documentatie

FastAPI publiceert doorgaans:

- Swagger UI: `/docs`
- ReDoc: `/redoc`
- OpenAPI JSON: `/openapi.json`

Controleer deze routes in de actieve deployment voordat ze extern worden gepubliceerd.
