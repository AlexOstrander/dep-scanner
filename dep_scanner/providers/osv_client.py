from __future__ import annotations

"""OSV.dev client and response normalization helpers."""

import httpx

from dep_scanner.models import Advisory, Dependency

OSV_QUERY_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL_TEMPLATE = "https://api.osv.dev/v1/vulns/{advisory_id}"
OSV_FALLBACK_LINK_TEMPLATE = "https://osv.dev/vulnerability/{advisory_id}"
OSV_REFERENCE_PRIORITY = ("ADVISORY", "FIX", "REPORT", "ARTICLE", "WEB", "PACKAGE", "EVIDENCE")


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

    advisory_enrichment_cache: dict[tuple[str, str], tuple[str, str, list[str], str, str, list[str]]] = {}

    for dependency, result in zip(dependencies, results, strict=False):
        vulnerabilities = result.get("vulns", []) if isinstance(result, dict) else []
        parsed_advisories: list[Advisory] = []
        for vulnerability in vulnerabilities:
            advisory_id = str(vulnerability.get("id", "OSV-UNKNOWN"))
            cve_ids = parse_osv_cve_ids(vulnerability)
            severity = parse_osv_severity(vulnerability, dependency)
            reference_url = parse_osv_reference_url(vulnerability, advisory_id)
            summary = str(vulnerability.get("summary", "")).strip()
            details = str(vulnerability.get("details", "")).strip()
            fixed_versions = parse_osv_fixed_versions(vulnerability, dependency)
            if severity == "UNKNOWN" or not reference_url or not fixed_versions or not summary or not details or not cve_ids:
                (
                    enriched_severity,
                    enriched_reference_url,
                    enriched_fixed_versions,
                    enriched_summary,
                    enriched_details,
                    enriched_cve_ids,
                ) = enrich_osv_advisory(
                    advisory_id=advisory_id,
                    dependency=dependency,
                    http_client=http_client,
                    cache=advisory_enrichment_cache,
                )
                if severity == "UNKNOWN":
                    severity = enriched_severity
                if not reference_url:
                    reference_url = enriched_reference_url
                if not fixed_versions:
                    fixed_versions = enriched_fixed_versions
                if not summary:
                    summary = enriched_summary
                if not details:
                    details = enriched_details
                if not cve_ids:
                    cve_ids = enriched_cve_ids

            parsed_advisories.append(
                Advisory(
                    advisory_id=advisory_id,
                    source="OSV",
                    severity=severity,
                    cve_ids=cve_ids,
                    summary=summary,
                    details=details,
                    reference_url=reference_url,
                    fixed_versions=sorted(set(fixed_versions)),
                )
            )

        advisories_by_dependency[(dependency.ecosystem, dependency.name.lower(), dependency.version)] = parsed_advisories

    return advisories_by_dependency


def parse_osv_severity(vulnerability: dict, dependency: Dependency | None = None) -> str:
    """Prefer textual severity, then fallback to OSV score fields."""
    database_specific = vulnerability.get("database_specific", {})
    if isinstance(database_specific, dict):
        textual_severity = database_specific.get("severity")
        if textual_severity:
            return str(textual_severity).upper()

    if dependency is not None:
        matched_affected_entries = filter_affected_for_dependency(vulnerability, dependency)
        severity_from_match = parse_severity_from_affected_entries(matched_affected_entries)
        if severity_from_match:
            return severity_from_match

    all_affected_entries = vulnerability.get("affected", [])
    if isinstance(all_affected_entries, list):
        severity_from_any_affected = parse_severity_from_affected_entries(all_affected_entries)
        if severity_from_any_affected:
            return severity_from_any_affected

    return parse_top_level_severity(vulnerability)


def parse_severity_from_affected_entries(affected_entries: list) -> str | None:
    """Extract severity from matching affected entries."""
    for affected in affected_entries:
        if not isinstance(affected, dict):
            continue
        ecosystem_specific = affected.get("ecosystem_specific", {})
        if isinstance(ecosystem_specific, dict):
            eco_severity = ecosystem_specific.get("severity")
            if eco_severity:
                return str(eco_severity).upper()
        database_specific = affected.get("database_specific", {})
        if isinstance(database_specific, dict):
            db_severity = database_specific.get("severity")
            if db_severity:
                return str(db_severity).upper()
        affected_severity_entries = affected.get("severity", [])
        if affected_severity_entries and isinstance(affected_severity_entries, list):
            first_affected_severity = affected_severity_entries[0]
            if isinstance(first_affected_severity, dict):
                return str(first_affected_severity.get("score", "UNKNOWN"))
    return None


def parse_top_level_severity(vulnerability: dict) -> str:
    """Extract severity from top-level OSV severity list."""
    severity_entries = vulnerability.get("severity", [])
    if severity_entries and isinstance(severity_entries, list):
        first_severity = severity_entries[0]
        if isinstance(first_severity, dict):
            return str(first_severity.get("score", "UNKNOWN"))
    return "UNKNOWN"


def parse_osv_reference_url(vulnerability: dict, advisory_id: str) -> str:
    """Select advisory link from OSV references using type priority."""
    _ = advisory_id
    references = vulnerability.get("references", [])
    reference_candidates: list[tuple[str, str]] = []
    if references and isinstance(references, list):
        for reference in references:
            if not isinstance(reference, dict):
                continue
            url = str(reference.get("url", "")).strip()
            if not url or not (url.startswith("http://") or url.startswith("https://")):
                continue
            if "osv.dev/list?q=vuln" in url:
                continue
            ref_type = str(reference.get("type", "WEB")).upper()
            reference_candidates.append((ref_type, url))

    for preferred_type in OSV_REFERENCE_PRIORITY:
        for ref_type, url in reference_candidates:
            if ref_type == preferred_type:
                return url

    if reference_candidates:
        return reference_candidates[0][1]
    return ""


def parse_osv_fixed_versions(vulnerability: dict, dependency: Dependency | None = None) -> list[str]:
    """Extract fixed versions from OSV affected range events."""
    fixed_versions: list[str] = []
    affected_entries: list = []
    if dependency is not None:
        affected_entries = filter_affected_for_dependency(vulnerability, dependency)
    if not affected_entries:
        raw_entries = vulnerability.get("affected", [])
        if isinstance(raw_entries, list):
            affected_entries = raw_entries

    for affected in affected_entries:
        if not isinstance(affected, dict):
            continue
        for affected_range in affected.get("ranges", []):
            for event in affected_range.get("events", []):
                fixed_version = event.get("fixed")
                if fixed_version:
                    fixed_versions.append(str(fixed_version))
    return sorted(set(fixed_versions))


def parse_osv_cve_ids(vulnerability: dict) -> list[str]:
    """Extract CVE IDs from advisory aliases."""
    aliases = [alias for alias in vulnerability.get("aliases", []) if isinstance(alias, str)]
    return sorted({alias for alias in aliases if alias.startswith("CVE-")})


def enrich_osv_advisory(
    *,
    advisory_id: str,
    dependency: Dependency,
    http_client: httpx.Client,
    cache: dict[tuple[str, str], tuple[str, str, list[str], str, str, list[str]]],
) -> tuple[str, str, list[str], str, str, list[str]]:
    """Fetch advisory details once to backfill severity, URL, fix versions, summary/details, and CVEs."""
    cache_key = (advisory_id, dependency.name.lower())
    if cache_key in cache:
        return cache[cache_key]
    if not advisory_id or advisory_id == "OSV-UNKNOWN":
        return "UNKNOWN", "", [], "", "", []

    response = http_client.get(
        OSV_VULN_URL_TEMPLATE.format(advisory_id=advisory_id),
        timeout=20.0,
    )
    if response.status_code != 200:
        cache[cache_key] = ("UNKNOWN", "", [], "", "", [])
        return cache[cache_key]

    payload = response.json()
    severity = parse_osv_severity(payload, dependency)
    reference_url = parse_osv_reference_url(payload, advisory_id)
    fixed_versions = parse_osv_fixed_versions(payload, dependency)
    summary = str(payload.get("summary", "")).strip()
    details = str(payload.get("details", "")).strip()
    cve_ids = parse_osv_cve_ids(payload)
    cache[cache_key] = (severity, reference_url, fixed_versions, summary, details, cve_ids)
    return cache[cache_key]


def filter_affected_for_dependency(vulnerability: dict, dependency: Dependency) -> list[dict]:
    """Return affected entries matching the current dependency name/ecosystem."""
    affected_entries = vulnerability.get("affected", [])
    if not isinstance(affected_entries, list):
        return []

    matched: list[dict] = []
    dependency_name = dependency.name.strip().lower()
    dependency_ecosystem = dependency.ecosystem.strip().lower()
    for affected in affected_entries:
        if not isinstance(affected, dict):
            continue
        package_payload = affected.get("package", {})
        if not isinstance(package_payload, dict):
            continue
        package_name = str(package_payload.get("name", "")).strip().lower()
        package_ecosystem = str(package_payload.get("ecosystem", "")).strip().lower()
        if package_name != dependency_name:
            continue
        if package_ecosystem and package_ecosystem != dependency_ecosystem:
            continue
        matched.append(affected)
    return matched

