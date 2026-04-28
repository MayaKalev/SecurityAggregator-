"""Tests for nvd_client.nvd_get retry behavior. HTTP is mocked."""

import unittest
from http import HTTPStatus
from unittest.mock import MagicMock, patch
from clients.nvd_client import rate_limiter
from clients.nvd_client import nvd_get

import requests


class TestNvdGet(unittest.TestCase):

    def setUp(self) -> None:
        # Reset the module-level rate limiter so timestamps from previous
        # tests don't accumulate and trip the limit.

        rate_limiter._timestamps.clear()

    @patch("clients.nvd_client.time.sleep")
    @patch("clients.nvd_client.requests.get")
    def test_success_on_first_try(self, mock_get, _mock_sleep) -> None:
        mock_resp = MagicMock(status_code=HTTPStatus.OK)
        mock_resp.json.return_value = {"vulnerabilities": [], "totalResults": 0}
        mock_get.return_value = mock_resp

        from clients.nvd_client import nvd_get

        result = nvd_get({"cveId": "CVE-X"})

        self.assertEqual(result, {"vulnerabilities": [], "totalResults": 0})
        self.assertEqual(mock_get.call_count, 1)

    @patch("clients.nvd_client.time.sleep")
    @patch("clients.nvd_client.requests.get")
    def test_retry_on_too_many_then_success(self, mock_get, _mock_sleep) -> None:
        mock_429 = MagicMock(status_code=HTTPStatus.TOO_MANY_REQUESTS, headers={})
        mock_200 = MagicMock(status_code=HTTPStatus.OK)
        mock_200.json.return_value = {"ok": "second-try"}
        mock_get.side_effect = [mock_429, mock_200]

        result = nvd_get({"cveId": "CVE-X"})

        self.assertEqual(result, {"ok": "second-try"})
        self.assertEqual(mock_get.call_count, 2)

    @patch("clients.nvd_client.time.sleep")
    @patch("clients.nvd_client.requests.get")
    def test_exhausts_retries_on_persistent_server_error(self, mock_get, _mock_sleep) -> None:
        mock_500 = MagicMock(status_code=HTTPStatus.INTERNAL_SERVER_ERROR, headers={})
        mock_500.raise_for_status.side_effect = requests.HTTPError("500 Server Error")
        mock_get.return_value = mock_500
        with self.assertRaises(requests.HTTPError):
            nvd_get({"cveId": "CVE-X"})

        # 5 retry attempts (per _RETRY_ATTEMPTS).
        self.assertEqual(mock_get.call_count, 5)


if __name__ == "__main__":
    unittest.main()
