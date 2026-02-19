from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class CveRecord:
    cve_id: str
    summary: Optional[str] = None
    severity: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    published_at: Optional[str] = None
    sources: set[str] = field(default_factory=set)
    references: set[str] = field(default_factory=set)


@dataclass
class PendingGhsaRecord:
    ghsa_id: str
    summary: Optional[str] = None
    severity: Optional[str] = None
    published_at: Optional[str] = None
    references: set[str] = field(default_factory=set)
