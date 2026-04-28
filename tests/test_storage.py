"""Tests for the storage layer's public functions."""

import tempfile
import unittest
from pathlib import Path
import storage.storage as smod
from storage import store_findings
from storage import get_critical_findings
from storage import find_existing_modifications
from storage import get_latest_modification

class _DBTestCase(unittest.TestCase):
    """Base class — gives each test a fresh temp DB."""

    def setUp(self) -> None:


        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        tmp.close()
        self._tmp_path = Path(tmp.name)
        self._original_db_path = smod.DB_PATH
        smod.DB_PATH = self._tmp_path

    def tearDown(self) -> None:
        smod.DB_PATH = self._original_db_path
        self._tmp_path.unlink(missing_ok=True)



class TestStoreFindings(_DBTestCase):

    def test_happy_path_three_valid_items_all_stored(self) -> None:

        result = store_findings([
            {"cve_id": "CVE-A", "topics": ["rce"], "severity": "High", "summary": "a"},
            {"cve_id": "CVE-B", "topics": ["xss"], "severity": "Low", "summary": "b"},
            {"cve_id": "CVE-C", "topics": ["dos"], "severity": "Medium", "summary": "c"},
        ])

        self.assertTrue(result["ok"])
        self.assertEqual(result["stored"], 3)
        self.assertEqual(result["errors"], [])

    def test_validation_rejection_only_valid_stored_invalid_in_errors(self) -> None:

        result = store_findings([
            {"cve_id": "CVE-A", "topics": ["rce"], "severity": "High", "summary": "ok"},
            {"cve_id": "CVE-BAD", "topics": ["rce"], "severity": "NUKE", "summary": "bad sev"},
            {"cve_id": "", "topics": ["rce"], "severity": "High", "summary": "no id"},
            {"cve_id": "CVE-D", "topics": ["xss"], "severity": "Low", "summary": "ok"},
        ])

        self.assertEqual(result["stored"], 2)
        self.assertEqual(len(result["errors"]), 2)
        error_ids = {e["id"] for e in result["errors"]}
        self.assertEqual(error_ids, {"CVE-BAD", ""})

    def test_idempotent_replace_on_re_store(self) -> None:
        from storage import find_existing_modifications, store_findings

        store_findings([{
            "cve_id": "CVE-A",
            "topics": ["rce"],
            "severity": "High",
            "summary": "v1",
            "source_last_modified": "2026-04-01T00:00:00.000+00:00",
        }])
        store_findings([{
            "cve_id": "CVE-A",
            "topics": ["rce", "zero-day"],
            "severity": "Critical",
            "summary": "v2 (updated)",
            "source_last_modified": "2026-04-25T00:00:00.000+00:00",
        }])

        existing = find_existing_modifications(["CVE-A"])
        self.assertEqual(existing["CVE-A"], "2026-04-25T00:00:00.000+00:00")


class TestFindExistingModifications(_DBTestCase):

    def test_returns_existing_omits_unknown(self) -> None:

        store_findings([
            {"cve_id": "CVE-A", "topics": ["rce"], "severity": "High",
             "summary": "a", "source_last_modified": "2026-04-10T00:00:00.000+00:00"},
            {"cve_id": "CVE-B", "topics": ["xss"], "severity": "Low",
             "summary": "b", "source_last_modified": "2026-04-20T00:00:00.000+00:00"},
        ])

        result = find_existing_modifications(["CVE-A", "CVE-B", "CVE-MISSING"])

        self.assertEqual(result, {
            "CVE-A": "2026-04-10T00:00:00.000+00:00",
            "CVE-B": "2026-04-20T00:00:00.000+00:00",
        })
        self.assertNotIn("CVE-MISSING", result)

    def test_empty_input_returns_empty(self) -> None:
        from storage import find_existing_modifications

        self.assertEqual(find_existing_modifications([]), {})


class TestGetCriticalFindings(_DBTestCase):

    def test_filters_to_critical_omits_others(self) -> None:

        store_findings([
            {"cve_id": "CVE-CRIT", "topics": ["rce"], "severity": "Critical",
             "summary": "very bad", "source_url": "http://x/CRIT"},
            {"cve_id": "CVE-HIGH", "topics": ["xss"], "severity": "High",
             "summary": "bad", "source_url": "http://x/HIGH"},
            {"cve_id": "CVE-LOW", "topics": ["dos"], "severity": "Low",
             "summary": "meh", "source_url": "http://x/LOW"},
        ])

        result = get_critical_findings(["CVE-CRIT", "CVE-HIGH", "CVE-LOW", "CVE-MISSING"])

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["id"], "CVE-CRIT")
        self.assertEqual(result[0]["summary"], "very bad")

    def test_empty_input_returns_empty(self) -> None:
        from storage import get_critical_findings

        self.assertEqual(get_critical_findings([]), [])



class TestGetLatestModification(_DBTestCase):

    def test_empty_db_returns_none(self) -> None:
        from storage import get_latest_modification

        self.assertIsNone(get_latest_modification())

    def test_returns_max_across_rows(self) -> None:
        store_findings([
            {"cve_id": "CVE-A", "topics": ["rce"], "severity": "High",
             "summary": "a", "source_last_modified": "2026-04-10T00:00:00.000+00:00"},
            {"cve_id": "CVE-B", "topics": ["xss"], "severity": "Low",
             "summary": "b", "source_last_modified": "2026-04-25T15:30:00.000+00:00"},
            {"cve_id": "CVE-C", "topics": ["dos"], "severity": "Medium",
             "summary": "c", "source_last_modified": "2026-04-15T00:00:00.000+00:00"},
        ])

        self.assertEqual(get_latest_modification(), "2026-04-25T15:30:00.000+00:00")


if __name__ == "__main__":
    unittest.main()
