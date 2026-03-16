from __future__ import annotations

"""OSV.dev client and response normalization helpers."""

import httpx

from dep_scanner.models import Advisory, Dependency

OSV_QUERY_BATCH_URL = "https://api.osv.dev/v1/querybatch"


def query_osv(dependencies: list[Dependency], http_client: httpx.Client) -> dict[tuple[str, str, str], list[Advisory]]:
    """Batch query OSV and map advisories back to dependency keys."""
    if not dependencies:
        return {}

    queries = [
        {
            "package": {"name": dependency.name, "ecosystem": dependency.ecosystem},
            "version": dependency.version,
        }
        for dependency in dependencies
    ]

    response = http_client.post(
        OSV_QUERY_BATCH_URL,
        json={"queries": queries},
        timeout=30.0,
    )
    if response.status_code != 200:
        return {}

    payload = response.json()
    results = payload.get("results", [])
    advisories_by_dependency: dict[tuple[str, str, str], list[Advisory]] = {}

    for dependency, result in zip(dependencies, results, strict=False):
        vulnerabilities = result.get("vulns", []) if isinstance(result, dict) else []
        parsed_advisories: list[Advisory] = []
        for vulnerability in vulnerabilities:
            aliases = [alias for alias in vulnerability.get("aliases", []) if isinstance(alias, str)]
            cve_ids = [alias for alias in aliases if alias.startswith("CVE-")]
            severity_entries = vulnerability.get("severity", [])
            severity = "UNKNOWN"
            if severity_entries and isinstance(severity_entries, list):
                first_severity = severity_entries[0]
                if isinstance(first_severity, dict):
                    severity = str(first_severity.get("score", "UNKNOWN"))

            reference_url = ""
            references = vulnerability.get("references", [])
            if references and isinstance(references, list):
                first_ref = references[0]
                if isinstance(first_ref, dict):
                    reference_url = str(first_ref.get("url", ""))

            fixed_versions: list[str] = []
            for affected in vulnerability.get("affected", []):
                for affected_range in affected.get("ranges", []):
                    for event in affected_range.get("events", []):
                        fixed_version = event.get("fixed")
                        if fixed_version:
                            fixed_versions.append(str(fixed_version))

            parsed_advisories.append(
                Advisory(
                    advisory_id=str(vulnerability.get("id", "OSV-UNKNOWN")),
                    source="OSV",
                    severity=severity,
                    cve_ids=cve_ids,
                    summary=str(vulnerability.get("summary", "")),
                    details=str(vulnerability.get("details", "")),
                    reference_url=reference_url,
                    fixed_versions=sorted(set(fixed_versions)),
                )
            )

        advisories_by_dependency[(dependency.ecosystem, dependency.name.lower(), dependency.version)] = parsed_advisories

    return advisories_by_dependency

