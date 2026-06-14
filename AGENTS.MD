Modify the collector so it no longer syncs only the current month.

Requirements:

* Query the MSRC endpoint /updates first.
* Retrieve all available release IDs.
* Store release metadata and revision information.
* During a normal run, automatically synchronize:
    * current release
    * previous release
    * any release whose revision date changed since the last sync
* Add a last_synced_at field for releases.
* Add a daily scheduler container in docker-compose.
* Collector must be idempotent and safe to run multiple times per day.
* If a CVE changes (CVSS, severity, exploit status, product mapping, title, description), update existing records.
* Log how many releases, CVEs and products were added or updated.
* Exit with non-zero status only on actual synchronization failures.
