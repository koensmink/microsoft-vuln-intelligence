import os
import sys
from datetime import datetime, timezone

import httpx
from sqlalchemy import create_engine, text


MSRC_API_BASE_URL = os.getenv(
    "MSRC_API_BASE_URL",
    "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf",
)

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "sqlite+pysqlite:///./dev.db",
)


def utcnow():
    return datetime.now(timezone.utc)


def current_release_name() -> str:
    return utcnow().strftime("%Y-%b")


def fetch_release(release_name: str) -> dict:
    url = f"{MSRC_API_BASE_URL.rstrip('/')}/{release_name}"

    headers = {
        "Accept": "application/json",
        "User-Agent": "microsoft-vuln-intelligence/0.1",
    }

    with httpx.Client(timeout=60, follow_redirects=True, headers=headers) as client:
        response = client.get(url)

    content_type = response.headers.get("content-type", "")
    body_preview = response.text[:1000].replace("\n", " ").replace("\r", " ")

    if response.status_code != 200:
        raise RuntimeError(
            "MSRC request failed: "
            f"url={url}, "
            f"status={response.status_code}, "
            f"content_type={content_type}, "
            f"body_preview={body_preview}"
        )

    if "json" not in content_type.lower():
        raise RuntimeError(
            "MSRC response is not JSON: "
            f"url={url}, "
            f"status={response.status_code}, "
            f"content_type={content_type}, "
            f"body_preview={body_preview}"
        )

    try:
        return response.json()
    except ValueError as exc:
        raise RuntimeError(
            "MSRC JSON parsing failed: "
            f"url={url}, "
            f"status={response.status_code}, "
            f"content_type={content_type}, "
            f"body_preview={body_preview}"
        ) from exc


def parse_bool(value) -> bool:
    if isinstance(value, bool):
        return value

    if value is None:
        return False

    if isinstance(value, str):
        return value.strip().lower() in {"true", "yes", "1"}

    return bool(value)


def parse_cvrf(document: dict, release_name: str) -> dict:
    vulnerabilities = document.get("Vulnerability", []) or []

    parsed_cves = []

    for vulnerability in vulnerabilities:
        cve_id = vulnerability.get("CVE")

        if not cve_id:
            continue

        parsed_cves.append(
            {
                "cve_id": cve_id,
                "title": str(vulnerability.get("Title", ""))[:255],
                "description": str(vulnerability.get("Description", "")),
                "severity": vulnerability.get("Severity"),
                "impact": vulnerability.get("Impact"),
                "exploited": parse_bool(vulnerability.get("Exploited")),
                "publicly_disclosed": parse_bool(
                    vulnerability.get("PubliclyDisclosed")
                ),
            }
        )

    return {
        "release": {
            "release_name": release_name,
            "document_title": str(document.get("DocumentTitle", ""))[:255],
        },
        "cves": parsed_cves,
    }


def upsert(parsed: dict) -> None:
    engine = create_engine(DATABASE_URL, pool_pre_ping=True)

    with engine.begin() as conn:
        run_id = conn.execute(
            text(
                """
                INSERT INTO sync_runs
                    (started_at, status, records_processed)
                VALUES
                    (:started_at, 'running', 0)
                RETURNING id
                """
            ),
            {"started_at": utcnow()},
        ).scalar_one()

        try:
            release = parsed["release"]

            release_id = conn.execute(
                text(
                    """
                    INSERT INTO releases
                        (release_name, document_title, created_at)
                    VALUES
                        (:release_name, :document_title, :created_at)
                    ON CONFLICT (release_name)
                    DO UPDATE SET
                        document_title = EXCLUDED.document_title
                    RETURNING id
                    """
                ),
                {
                    "release_name": release["release_name"],
                    "document_title": release.get("document_title"),
                    "created_at": utcnow(),
                },
            ).scalar_one()

            count = 0

            for cve in parsed["cves"]:
                conn.execute(
                    text(
                        """
                        INSERT INTO cves
                            (
                                cve_id,
                                title,
                                description,
                                severity,
                                impact,
                                exploited,
                                publicly_disclosed,
                                release_id,
                                created_at,
                                updated_at
                            )
                        VALUES
                            (
                                :cve_id,
                                :title,
                                :description,
                                :severity,
                                :impact,
                                :exploited,
                                :publicly_disclosed,
                                :release_id,
                                :created_at,
                                :updated_at
                            )
                        ON CONFLICT (cve_id)
                        DO UPDATE SET
                            title = EXCLUDED.title,
                            description = EXCLUDED.description,
                            severity = EXCLUDED.severity,
                            impact = EXCLUDED.impact,
                            exploited = EXCLUDED.exploited,
                            publicly_disclosed = EXCLUDED.publicly_disclosed,
                            release_id = EXCLUDED.release_id,
                            updated_at = EXCLUDED.updated_at
                        """
                    ),
                    {
                        **cve,
                        "release_id": release_id,
                        "created_at": utcnow(),
                        "updated_at": utcnow(),
                    },
                )

                count += 1

            conn.execute(
                text(
                    """
                    UPDATE sync_runs
                    SET
                        finished_at = :finished_at,
                        status = 'success',
                        records_processed = :records_processed
                    WHERE id = :id
                    """
                ),
                {
                    "finished_at": utcnow(),
                    "records_processed": count,
                    "id": run_id,
                },
            )

        except Exception as exc:
            conn.execute(
                text(
                    """
                    UPDATE sync_runs
                    SET
                        finished_at = :finished_at,
                        status = 'failed',
                        error_message = :error_message
                    WHERE id = :id
                    """
                ),
                {
                    "finished_at": utcnow(),
                    "error_message": str(exc)[:4000],
                    "id": run_id,
                },
            )

            raise


def main() -> None:
    release_name = sys.argv[1] if len(sys.argv) > 1 else current_release_name()

    document = fetch_release(release_name)
    parsed = parse_cvrf(document, release_name)
    upsert(parsed)

    print(f"synced {release_name}: {len(parsed['cves'])} CVEs")


if __name__ == "__main__":
    main()
