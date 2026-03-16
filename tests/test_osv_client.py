from dep_scanner.models import Dependency
from dep_scanner.providers.osv_client import (
    parse_osv_cve_ids,
    parse_osv_fixed_versions,
    parse_osv_reference_url,
    parse_osv_severity,
)


def test_parse_osv_reference_url_prefers_reference_types() -> None:
    vulnerability = {
        "references": [
            {"type": "WEB", "url": "https://example.com/web"},
            {"type": "FIX", "url": "https://example.com/fix-commit"},
        ]
    }
    assert parse_osv_reference_url(vulnerability, "GHSA-xxxx-yyyy-zzzz") == "https://example.com/fix-commit"


def test_parse_osv_reference_url_ignores_generic_list_link() -> None:
    vulnerability = {
        "references": [
            {"type": "WEB", "url": "https://osv.dev/list?q=vuln"},
        ]
    }
    assert parse_osv_reference_url(vulnerability, "GHSA-h466-j336-74wx") == ""


def test_parse_osv_severity_uses_affected_severity_when_present() -> None:
    vulnerability = {
        "affected": [
            {
                "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:N/A:N"}],
            }
        ]
    }
    assert parse_osv_severity(vulnerability) == "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:N/A:N"


def test_parse_osv_cve_ids_from_aliases() -> None:
    vulnerability = {"aliases": ["GHSA-h466-j336-74wx", "CVE-2018-16490", "CVE-2019-00001"]}
    assert parse_osv_cve_ids(vulnerability) == ["CVE-2018-16490", "CVE-2019-00001"]


def test_parse_osv_fixed_versions_filters_to_matching_package() -> None:
    vulnerability = {
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "express"},
                "ranges": [{"events": [{"introduced": "0"}, {"fixed": "4.20.0"}]}],
            },
            {
                "package": {"ecosystem": "npm", "name": "other-package"},
                "ranges": [{"events": [{"introduced": "0"}, {"fixed": "9.9.9"}]}],
            },
        ]
    }
    dependency = Dependency(name="express", version="4.19.2", ecosystem="npm", is_direct=True, source="test")
    assert parse_osv_fixed_versions(vulnerability, dependency) == ["4.20.0"]


def test_parse_osv_severity_prefers_matching_affected_ecosystem_specific() -> None:
    vulnerability = {
        "affected": [
            {
                "package": {"ecosystem": "crates.io", "name": "http"},
                "ecosystem_specific": {"severity": "HIGH"},
            },
            {
                "package": {"ecosystem": "crates.io", "name": "other"},
                "ecosystem_specific": {"severity": "LOW"},
            },
        ]
    }
    dependency = Dependency(name="http", version="0.1.19", ecosystem="crates.io", is_direct=True, source="test")
    assert parse_osv_severity(vulnerability, dependency) == "HIGH"

