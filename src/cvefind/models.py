from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class CveRecord:
    cve_id: str
    summary: str | None = None
    severity: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    published_at: str | None = None
    sources: set[str] = field(default_factory=set)
    references: set[str] = field(default_factory=set)


@dataclass
class PendingGhsaRecord:
    ghsa_id: str
    summary: str | None = None
    severity: str | None = None
    published_at: str | None = None
    references: set[str] = field(default_factory=set)
