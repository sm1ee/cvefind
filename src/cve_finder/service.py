from __future__ import annotations

import asyncio
from typing import Any

from cve_finder.aliases import get_aliases
from cve_finder.collectors import collect_from_ghsa, collect_from_nvd, collect_from_osv
from cve_finder.models import CveRecord, PendingGhsaRecord

OSV_ECOSYSTEM_MAP = {
    "npm": "npm",
    "pypi": "PyPI",
    "maven": "Maven",
    "nuget": "NuGet",
    "go": "Go",
    "packagist": "Packagist",
    "rubygems": "RubyGems",
    "cargo": "crates.io",
}


def normalize_ecosystem(ecosystem: str) -> str:
    key = ecosystem.strip().lower()
    if key not in OSV_ECOSYSTEM_MAP:
        supported = ", ".join(sorted(OSV_ECOSYSTEM_MAP))
        raise ValueError(f"Unsupported ecosystem '{ecosystem}'. Supported: {supported}")
    return key


SEVERITY_RANK = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "moderate": 2,
    "low": 1,
    "unknown": 0,
}


def _severity_rank(value: str | None) -> int:
    if not value:
        return -1
    return SEVERITY_RANK.get(value.strip().lower(), -1)


def _normalize_severity_filter(value: str | None) -> str | None:
    if not value:
        return None
    normalized = value.strip().lower()
    if normalized not in SEVERITY_RANK:
        allowed = ", ".join(["critical", "high", "medium", "moderate", "low"])
        raise ValueError(f"Unsupported min_severity '{value}'. Supported: {allowed}")
    return normalized


def _is_more_recent(left: str | None, right: str | None) -> bool:
    if left and not right:
        return True
    if not left:
        return False
    return left > right


def _merge(records: list[CveRecord]) -> list[CveRecord]:
    merged: dict[str, CveRecord] = {}
    for record in records:
        existing = merged.get(record.cve_id)
        if not existing:
            merged[record.cve_id] = CveRecord(
                cve_id=record.cve_id,
                summary=record.summary,
                severity=record.severity,
                cvss_score=record.cvss_score,
                cvss_vector=record.cvss_vector,
                published_at=record.published_at,
                sources=set(record.sources),
                references=set(record.references),
            )
            continue
        if not existing.summary and record.summary:
            existing.summary = record.summary
        if _severity_rank(record.severity) > _severity_rank(existing.severity):
            existing.severity = record.severity
        if record.cvss_score is not None and (
            existing.cvss_score is None or record.cvss_score > existing.cvss_score
        ):
            existing.cvss_score = record.cvss_score
            if record.cvss_vector:
                existing.cvss_vector = record.cvss_vector
        elif not existing.cvss_vector and record.cvss_vector:
            existing.cvss_vector = record.cvss_vector
        if _is_more_recent(record.published_at, existing.published_at):
            existing.published_at = record.published_at
        existing.sources.update(record.sources)
        existing.references.update(record.references)
    return sorted(
        merged.values(),
        key=lambda x: (x.published_at or "", x.cve_id),
        reverse=True,
    )


def _filter_by_severity(
    records: list[CveRecord],
    min_severity: str | None,
) -> list[CveRecord]:
    if not min_severity:
        return records
    threshold = _severity_rank(min_severity)
    return [record for record in records if _severity_rank(record.severity) >= threshold]


def _filter_pending_by_severity(
    records: list[PendingGhsaRecord],
    min_severity: str | None,
) -> list[PendingGhsaRecord]:
    if not min_severity:
        return records
    threshold = _severity_rank(min_severity)
    return [record for record in records if _severity_rank(record.severity) >= threshold]


def _sort_pending(records: list[PendingGhsaRecord]) -> list[PendingGhsaRecord]:
    return sorted(
        records,
        key=lambda x: (x.published_at or "", x.ghsa_id),
        reverse=True,
    )


async def find_cves(
    package_name: str,
    ecosystem: str = "npm",
    extra_aliases: list[str] | None = None,
    include_ghsa_pending: bool = False,
    min_severity: str | None = None,
    timeout_sec: float = 20.0,
) -> dict[str, Any]:
    ecosystem_key = normalize_ecosystem(ecosystem)
    severity_filter = _normalize_severity_filter(min_severity)
    osv_ecosystem = OSV_ECOSYSTEM_MAP[ecosystem_key]
    aliases = get_aliases(ecosystem_key, package_name)
    if extra_aliases:
        aliases.update(a.strip() for a in extra_aliases if a.strip())
    query_terms = {package_name, *aliases}

    collected: list[CveRecord] = []
    pending_ghsa: list[PendingGhsaRecord] = []
    errors: dict[str, str] = {}

    import httpx

    async with httpx.AsyncClient(timeout=timeout_sec) as client:
        jobs = {
            "osv": collect_from_osv(client, osv_ecosystem, package_name),
            "ghsa": collect_from_ghsa(client, ecosystem_key, package_name),
            "nvd": collect_from_nvd(client, query_terms),
        }
        results = await asyncio.gather(*jobs.values(), return_exceptions=True)

    for source, result in zip(jobs.keys(), results):
        if isinstance(result, Exception):
            errors[source] = str(result)
            continue
        if source == "ghsa":
            ghsa_cves, ghsa_pending = result
            collected.extend(ghsa_cves)
            pending_ghsa.extend(ghsa_pending)
            continue
        collected.extend(result)

    merged = _filter_by_severity(_merge(collected), severity_filter)
    result: dict[str, Any] = {
        "package": package_name,
        "ecosystem": ecosystem_key,
        "aliases_used": sorted(aliases),
        "min_severity": severity_filter,
        "count": len(merged),
        "cves": [
            {
                "cve_id": record.cve_id,
                "severity": record.severity,
                "cvss_score": record.cvss_score,
                "cvss_vector": record.cvss_vector,
                "published_at": record.published_at,
                "summary": record.summary,
                "sources": sorted(record.sources),
                "references": sorted(record.references),
            }
            for record in merged
        ],
        "errors": errors,
    }
    if include_ghsa_pending:
        pending = _sort_pending(_filter_pending_by_severity(pending_ghsa, severity_filter))
        result["pending_ghsa_count"] = len(pending)
        result["pending_ghsa"] = [
            {
                "ghsa_id": item.ghsa_id,
                "severity": item.severity,
                "published_at": item.published_at,
                "summary": item.summary,
                "references": sorted(item.references),
            }
            for item in pending
        ]
    return result
