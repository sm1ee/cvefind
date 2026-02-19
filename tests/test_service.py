import unittest

from cvefind.models import CveRecord, PendingGhsaRecord
from cvefind.service import (
    _filter_by_severity,
    _filter_pending_by_severity,
    _merge,
    normalize_ecosystem,
)


class ServiceTests(unittest.TestCase):
    def test_merge_combines_sources_and_references(self) -> None:
        records = [
            CveRecord(
                cve_id="CVE-2024-12345",
                summary="first",
                severity=None,
                cvss_score=None,
                cvss_vector=None,
                published_at="2024-01-01T00:00:00Z",
                sources={"osv"},
                references={"https://a"},
            ),
            CveRecord(
                cve_id="CVE-2024-12345",
                summary=None,
                severity="high",
                cvss_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                published_at="2024-03-01T00:00:00Z",
                sources={"ghsa"},
                references={"https://b"},
            ),
        ]
        merged = _merge(records)

        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].cve_id, "CVE-2024-12345")
        self.assertEqual(merged[0].severity, "high")
        self.assertEqual(merged[0].cvss_score, 9.8)
        self.assertEqual(
            merged[0].cvss_vector,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        )
        self.assertEqual(merged[0].published_at, "2024-03-01T00:00:00Z")
        self.assertEqual(merged[0].sources, {"osv", "ghsa"})
        self.assertEqual(merged[0].references, {"https://a", "https://b"})

    def test_normalize_ecosystem_supports_npm(self) -> None:
        self.assertEqual(normalize_ecosystem("NPM"), "npm")

    def test_filter_by_min_severity(self) -> None:
        records = [
            CveRecord(cve_id="CVE-2024-1", severity="critical"),
            CveRecord(cve_id="CVE-2024-2", severity="high"),
            CveRecord(cve_id="CVE-2024-3", severity="medium"),
            CveRecord(cve_id="CVE-2024-4", severity=None),
        ]
        filtered = _filter_by_severity(records, "high")
        self.assertEqual([item.cve_id for item in filtered], ["CVE-2024-1", "CVE-2024-2"])

    def test_filter_pending_by_min_severity(self) -> None:
        records = [
            PendingGhsaRecord(ghsa_id="GHSA-a", severity="high"),
            PendingGhsaRecord(ghsa_id="GHSA-b", severity="low"),
        ]
        filtered = _filter_pending_by_severity(records, "high")
        self.assertEqual([item.ghsa_id for item in filtered], ["GHSA-a"])


if __name__ == "__main__":
    unittest.main()
