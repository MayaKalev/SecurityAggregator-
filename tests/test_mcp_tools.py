"""Tests for the MCP-style tools' validation + send_critical_alert flow."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from tools import fetch_security_data
import storage.storage as smod
from tools import send_critical_alert
from storage import store_findings


class TestFetchSecurityDataValidation(unittest.TestCase):

    def test_no_selection_mode_rejected(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            fetch_security_data()

        self.assertIn("must specify a selection mode", str(ctx.exception))

    def test_cve_ids_takes_precedence_over_dates(self) -> None:
        """When both cve_ids and dates are passed, cve_ids wins (dates ignored)."""
        with patch("tools.mcp_tools.fetch_by_cve_ids") as mock_fetch:
            mock_fetch.return_value = {
                "items": [], "total_results": 0,
                "start_index": 0, "results_per_page": 0,
                "next_start_index": None,
            }
            fetch_security_data(
                cve_ids=["CVE-X"],
                last_mod_start_date="2026-04-01T00:00:00",
                last_mod_end_date="2026-04-25T00:00:00",
            )

        mock_fetch.assert_called_once_with(["CVE-X"])

    def test_lone_date_param_rejected(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            fetch_security_data(last_mod_start_date="2026-04-01T00:00:00")

        self.assertIn("must be passed together", str(ctx.exception))


class TestSendCriticalAlert(unittest.TestCase):

    def setUp(self) -> None:
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        tmp.close()
        self._tmp_path = Path(tmp.name)
        self._original_db_path = smod.DB_PATH
        smod.DB_PATH = self._tmp_path

    def tearDown(self) -> None:
        smod.DB_PATH = self._original_db_path
        self._tmp_path.unlink(missing_ok=True)

    def test_empty_input_no_email_no_lookup(self) -> None:
        with patch("tools.mcp_tools.send_email") as mock_send:
            result = send_critical_alert([])

        mock_send.assert_not_called()
        self.assertEqual(result["criticals"], 0)
        self.assertTrue(result["ok"])

    def test_no_criticals_among_ids_no_email_sent(self) -> None:
        store_findings([
            {"cve_id": "CVE-LOW", "topics": ["xss"], "severity": "Low", "summary": "meh"},
            {"cve_id": "CVE-HIGH", "topics": ["rce"], "severity": "High", "summary": "bad"},
        ])

        with patch("tools.mcp_tools.send_email") as mock_send:
            result = send_critical_alert(["CVE-LOW", "CVE-HIGH"])

        mock_send.assert_not_called()
        self.assertEqual(result["criticals"], 0)
        self.assertTrue(result["ok"])

    def test_critical_present_email_sent_once_with_right_subject(self) -> None:
        store_findings([
            {"cve_id": "CVE-CRIT", "topics": ["rce"], "severity": "Critical",
             "summary": "remote code execution", "source_url": "http://x/CRIT"},
            {"cve_id": "CVE-LOW", "topics": ["xss"], "severity": "Low", "summary": "meh"},
        ])

        with patch("tools.mcp_tools.send_email") as mock_send:
            mock_send.return_value = {
                "ok": True, "sent": 1, "dry_run": False,
                "to": ["dest@example.com"], "error": None,
            }
            result = send_critical_alert(["CVE-CRIT", "CVE-LOW"])

        mock_send.assert_called_once()
        subject, body = mock_send.call_args[0]
        self.assertIn("1 Critical CVE(s) detected", subject)
        self.assertIn("CVE-CRIT", body)
        self.assertNotIn("CVE-LOW", body)
        self.assertEqual(result["criticals"], 1)
        self.assertTrue(result["ok"])


if __name__ == "__main__":
    unittest.main()
