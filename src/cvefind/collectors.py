from __future__ import annotations

import os
import re
from typing import Any, Optional

from cvefind.models import CveRecord, PendingGhsaRecord

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def _clean_cve(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    candidate = value.strip().upper()
    if CVE_RE.match(candidate):
        return candidate
    return None


def _first_description(items: Optional[list[dict[str, Any]]]) -> Optional[str]:
    if not items:
        return None
    for item in items:
        value = item.get("value")
        if value:
            return value.strip()
    return None


def _extract_nvd_severity(metrics: Optional[dict[str, Any]]) -> Optional[str]:
    if not metrics:
        return None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        items = metrics.get(key) or []
        if not items:
            continue
        level = (
            items[0].get("cvssData", {}).get("baseSeverity")
            or items[0].get("baseSeverity")
        )
        if level:
            return str(level).lower()
    return None


def _extract_nvd_cvss_score(metrics: Optional[dict[str, Any]]) -> Optional[float]:
    if not metrics:
        return None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        items = metrics.get(key) or []
        if not items:
            continue
        score = (
            items[0].get("cvssData", {}).get("baseScore")
            or items[0].get("baseScore")
        )
        if score is None:
            continue
        try:
            return float(score)
        except (TypeError, ValueError):
            continue
    return None


def _extract_nvd_cvss_vector(metrics: Optional[dict[str, Any]]) -> Optional[str]:
    if not metrics:
        return None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        items = metrics.get(key) or []
        if not items:
            continue
        vector = items[0].get("cvssData", {}).get("vectorString")
        if vector:
            return str(vector)
    return None


async def collect_from_osv(
    client: Any,
    ecosystem: str,
    package_name: str,
) -> list[CveRecord]:
    payload = {"package": {"ecosystem": ecosystem, "name": package_name}}
    res = await client.post("https://api.osv.dev/v1/query", json=payload)
    res.raise_for_status()
    data = res.json()
    records: list[CveRecord] = []

    for vuln in data.get("vulns", []):
        candidate_ids: set[str] = set()
        maybe_cve = _clean_cve(vuln.get("id"))
        if maybe_cve:
            candidate_ids.add(maybe_cve)
        for alias in vuln.get("aliases", []):
            maybe_alias = _clean_cve(alias)
            if maybe_alias:
                candidate_ids.add(maybe_alias)
        if not candidate_ids:
            continue

        references = {
            ref.get("url")
            for ref in vuln.get("references", [])
            if isinstance(ref, dict) and ref.get("url")
        }
        summary = vuln.get("summary")
        severity = vuln.get("database_specific", {}).get("severity")
        published_at = vuln.get("published")

        for cve_id in sorted(candidate_ids):
            records.append(
                CveRecord(
                    cve_id=cve_id,
                    summary=summary,
                    severity=severity,
                    cvss_score=None,
                    cvss_vector=None,
                    published_at=published_at,
                    sources={"osv"},
                    references=references,
                )
            )
    return records


async def collect_from_ghsa(
    client: Any,
    ecosystem: str,
    package_name: str,
) -> tuple[list[CveRecord], list[PendingGhsaRecord]]:
    headers = {"Accept": "application/vnd.github+json"}
    token = os.getenv("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    params = {
        "ecosystem": ecosystem.lower(),
        "affects": package_name,
        "per_page": "100",
    }
    res = await client.get(
        "https://api.github.com/advisories",
        headers=headers,
        params=params,
    )
    res.raise_for_status()
    advisories = res.json()
    records: list[CveRecord] = []
    pending: list[PendingGhsaRecord] = []

    for advisory in advisories:
        candidate_ids: set[str] = set()
        cve_id = _clean_cve(advisory.get("cve_id"))
        if cve_id:
            candidate_ids.add(cve_id)

        for identifier in advisory.get("identifiers", []):
            maybe = _clean_cve(identifier.get("value"))
            if maybe:
                candidate_ids.add(maybe)
        references = set()
        url = advisory.get("html_url")
        if url:
            references.add(url)
        summary = advisory.get("summary")
        severity = str(advisory.get("severity") or "").lower() or None
        ghsa_id = advisory.get("ghsa_id")
        published_at = advisory.get("published_at")

        if not candidate_ids:
            if ghsa_id:
                pending.append(
                    PendingGhsaRecord(
                        ghsa_id=ghsa_id,
                        summary=summary,
                        severity=severity,
                        published_at=published_at,
                        references=references,
                    )
                )
            continue

        for cve in sorted(candidate_ids):
            records.append(
                CveRecord(
                    cve_id=cve,
                    summary=summary,
                    severity=severity,
                    cvss_score=None,
                    cvss_vector=None,
                    published_at=published_at,
                    sources={"ghsa"},
                    references=references,
                )
            )
    return records, pending


def _nvd_match_relevance(cve: dict[str, Any], query_terms: set[str]) -> bool:
    description = _first_description(cve.get("descriptions")) or ""
    blob = description.lower()
    if any(term in blob for term in query_terms):
        return True

    configurations = cve.get("configurations", [])
    for conf in configurations:
        for node in conf.get("nodes", []):
            for cpe in node.get("cpeMatch", []):
                criteria = str(cpe.get("criteria", "")).lower()
                if any(term in criteria for term in query_terms):
                    return True
    return False


async def collect_from_nvd(
    client: Any,
    query_terms: set[str],
) -> list[CveRecord]:
    headers: dict[str, str] = {}
    api_key = os.getenv("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key

    records: list[CveRecord] = []
    for term in sorted(query_terms):
        if not term.strip():
            continue
        res = await client.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"keywordSearch": term, "resultsPerPage": "200"},
            headers=headers,
        )
        res.raise_for_status()
        payload = res.json()
        vulns = payload.get("vulnerabilities", [])
        for entry in vulns:
            cve = entry.get("cve", {})
            cve_id = _clean_cve(cve.get("id"))
            if not cve_id:
                continue
            if not _nvd_match_relevance(cve, {term.lower()}):
                continue
            summary = _first_description(cve.get("descriptions"))
            references = {
                ref.get("url")
                for ref in cve.get("references", [])
                if isinstance(ref, dict) and ref.get("url")
            }
            records.append(
                CveRecord(
                    cve_id=cve_id,
                    summary=summary,
                    severity=_extract_nvd_severity(cve.get("metrics")),
                    cvss_score=_extract_nvd_cvss_score(cve.get("metrics")),
                    cvss_vector=_extract_nvd_cvss_vector(cve.get("metrics")),
                    published_at=cve.get("published"),
                    sources={"nvd"},
                    references=references,
                )
            )
    return records
