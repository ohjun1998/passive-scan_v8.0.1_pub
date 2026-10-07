import re
import unittest
from urllib.parse import parse_qs, urlsplit
from unittest.mock import patch

import ai_review


class Response:
    def __init__(self, status, body, content_type="text/plain"):
        self.status = status
        self.body = body
        self.headers = {"Content-Type": content_type}

    def read(self, limit):
        return self.body[:limit]

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


class OwnedFileOpener:
    def __init__(self):
        self.requests = []
        self.marker = None

    def open(self, request, timeout):
        self.requests.append(request)
        if request.get_method() == "POST":
            self.marker = re.search(rb"review-[0-9a-f]{12}", request.data).group()
            return Response(201, b"created")
        return Response(200, self.marker)


class HtmlOpener:
    def open(self, request, timeout):
        value = parse_qs(urlsplit(request.full_url).query)["q"][0]
        return Response(200, f"<html><body>{value}</body></html>".encode(), "text/html")


class BooleanOpener:
    def __init__(self):
        self.requests = []

    def open(self, request, timeout):
        self.requests.append(request)
        value = parse_qs(urlsplit(request.full_url).query)["id"][0]
        return Response(200, b"OWN_SQL_MARKER" if "AND 1=2" not in value else b"")


class VerificationTests(unittest.TestCase):
    @patch("ai_review.socket.getaddrinfo", return_value=[(None, None, None, None, ("93.184.216.34", 443))])
    @patch("ai_review.time.sleep")
    def test_upload_readback_uses_exact_url_and_other_identity(self, pause, dns):
        url = "https://example.test/upload"
        readback = "https://example.test/files/my-owned-test.txt"
        config = {"allowed_hosts": ["example.test"],
                  "live_path_prefixes": ["/upload", "/files/"],
                  "max_http_requests": 4, "min_seconds_per_host": 1,
                  "enabled_test_kinds": ["upload", "upload_verify"],
                  "active_tests": {url: {"upload": {
                      "field": "file", "identity": "a", "verify_url": readback,
                      "verify_identity": "b"}}}}
        opener = OwnedFileOpener()
        client = ai_review.HttpClient(ai_review.Policy(config),
                                      {"a": "account-a", "b": "account-b"}, opener)
        report = {"observations": []}
        upload, _ = ai_review.execute_action(config, url, "upload", report, client)
        report["observations"].append(upload)
        verify, _ = ai_review.execute_action(config, url, "upload_verify", report, client)
        report["observations"].append(verify)
        self.assertEqual([r.get_method() for r in opener.requests], ["POST", "GET"])
        self.assertEqual(opener.requests[1].full_url, readback)
        self.assertEqual(opener.requests[1].get_header("Authorization"), "Bearer account-b")
        self.assertTrue(verify["upload_marker_present"])
        findings = ai_review.assess(report["observations"],
                                     {"uploaded_file_must_be_private": True}, url)
        self.assertEqual(findings[0]["kind"], "uploaded_file_exposure")
        self.assertEqual(findings[0]["evidence_ids"], ["obs-1", "obs-2"])
        self.assertEqual(client.policy.request_count, 2)

    def test_owned_download_compares_marker_across_accounts(self):
        url = "https://example.test/files/123"
        expectation = {"owner": "a", "private_marker": "OWN_TEST_FILE",
                       "other_account_must_be_denied": True}
        self.assertIn("download_access", ai_review.classify(url))
        observations = [{"action": identity, "status": 200, "marker_present": True,
                         "body_truncated": False} for identity in ("a", "b")]
        findings = ai_review.assess(observations, expectation, url)
        self.assertEqual(findings[0]["kind"], "download_access")
        self.assertEqual(findings[0]["evidence_ids"], ["obs-1", "obs-2"])

    @patch("ai_review.browser_canary", return_value=True)
    @patch("ai_review.socket.getaddrinfo", return_value=[(None, None, None, None, ("93.184.216.34", 443))])
    def test_xss_execution_requires_browser_evidence(self, dns, browser):
        url = "https://example.test/search?q=plain"
        config = {"allowed_hosts": ["example.test"], "live_path_prefixes": ["/search"],
                  "max_http_requests": 2, "min_seconds_per_host": 1}
        client = ai_review.HttpClient(ai_review.Policy(config), {}, HtmlOpener())
        observation, _ = client.configured_test(url, "xss_browser", {"parameter": "q"})
        self.assertTrue(observation["script_executed"])
        self.assertEqual(ai_review.assess([observation], {}, url)[0]["kind"], "xss_execution")
        browser.assert_called_once()

    def test_truncated_download_cannot_be_marked_no_signal(self):
        hypothesis = [{"kind": "download_access", "status": "not_tested"}]
        observations = [{"action": "a", "status": 200, "marker_present": True,
                         "body_truncated": False},
                        {"action": "b", "status": 403, "marker_present": False,
                         "body_truncated": True}]
        ai_review.update_hypotheses(hypothesis, observations, [],
                                    {"owner": "a", "private_marker": "OWN_TEST_FILE"})
        self.assertEqual(hypothesis[0]["status"], "not_tested")

    @patch("ai_review.socket.getaddrinfo", return_value=[(None, None, None, None, ("93.184.216.34", 443))])
    @patch("ai_review.time.sleep")
    def test_boolean_comparison_requires_owned_baseline_and_four_checks(self, pause, dns):
        url = "https://example.test/items?id=123"
        config = {"allowed_hosts": ["example.test"], "live_path_prefixes": ["/items"],
                  "max_http_requests": 6, "min_seconds_per_host": 1,
                  "enabled_test_kinds": ["sql_boolean"],
                  "active_tests": {url: {"sql_boolean": {"parameter": "id"}}},
                  "expectations": {url: {"sql_marker": "OWN_SQL_MARKER"}}}
        opener = BooleanOpener()
        client = ai_review.HttpClient(ai_review.Policy(config), {}, opener)
        baseline, raw = ai_review.execute_action(config, url, "anonymous", {}, client)
        baseline["sql_marker_present"] = b"OWN_SQL_MARKER" in raw
        report = {"observations": [baseline]}
        comparison, _ = ai_review.execute_action(config, url, "sql_boolean", report, client)
        self.assertTrue(comparison["sql_differential"])
        self.assertEqual([x["condition"] for x in comparison["checks"]],
                         ["true", "false", "false", "true"])
        self.assertEqual(client.policy.request_count, 5)
        findings = ai_review.assess([baseline, comparison], config["expectations"][url], url)
        self.assertEqual(findings[0]["kind"], "sql_boolean_differential")
        self.assertEqual(findings[0]["evidence_ids"], ["obs-1", "obs-2"])


if __name__ == "__main__":
    unittest.main()
