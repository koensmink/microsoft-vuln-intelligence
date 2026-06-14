Architecture Rules

Source Ownership

MSRC is the authoritative source for:

* Releases
* CVEs
* Product mappings
* Remediation information
* Microsoft-provided impact classifications

MSRC data must never be overwritten by external sources.

External Enrichment

External intelligence sources must be implemented as separate enrichment services.

Examples:

* NVD
* FIRST EPSS
* CISA KEV
* ExploitDB
* VulnCheck
* OpenCVE

Do not add external source logic to the MSRC collector.

Data Separation

Store enrichment data separately from MSRC data.

Preferred model:

* releases
* cves
* products
* cve_products
* cve_enrichment

The backend may aggregate data for presentation, but data ownership must remain clear.

Service Design

Collectors gather source data.

Enrichment workers enrich existing data.

A failure in an enrichment source must never block MSRC collection.

All enrichment processes must be idempotent and safe to rerun.

Precedence

When multiple sources provide similar information:

1. MSRC
2. NVD
3. CISA KEV
4. FIRST EPSS
5. Derived values

Never overwrite a higher-priority source with a lower-priority source.
