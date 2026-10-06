import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import ai_review


class FakeResponse:
    status = 200
    headers = {"Content-Type": "text/plain"}

    def read(self, limit):
        return b"normal result"[:limit]

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


class Opener:
    def __init__(self):
        self.requests = []

    def open(self, request, timeout):
        self.requests.append(request)
        return FakeResponse()


class Planner:
    def __init__(self):
        self.actions = iter(["anonymous", "sql_error", "stop"])

    def choose(self, url, available, observations):
        action = next(self.actions)
        assert action in available or action == "stop", (action, available)
        return {"action": action, "reason": "Compare the observed baseline"}


class AdaptiveReviewTests(unittest.TestCase):
    def setUp(self):
        self.url = "https://example.test/search?q=shoes"
        self.config = {
            "allowed_hosts": ["example.test"], "live_path_prefixes": ["/search", "/upload"],
            "max_urls": 2, "max_http_requests": 5, "min_seconds_per_host": 1,
            "enabled_test_kinds": ["reflection", "sql_error", "upload"],
            "active_tests": {self.url: {"sql_error": {"parameter": "q"}}},
        }

    def test_url_candidates_require_explicit_templates(self):
        candidates = {x["kind"]: x for x in ai_review.test_candidates(self.url, self.config)}
        self.assertEqual(candidates["sql_error"]["status"], "ready")
        self.assertEqual(candidates["reflection"]["status"], "ready")
        upload = ai_review.test_candidates("https://example.test/upload", self.config)[0]
        self.assertEqual(upload["status"], "needs_configuration")
        self.assertNotIn("upload", ai_review.available_actions("https://example.test/upload", {}, set(), self.config))

    def test_dry_run_lists_candidates_without_requests(self):
        opener = Opener()
        client = ai_review.HttpClient(ai_review.Policy(self.config), {}, opener)
        with tempfile.TemporaryDirectory() as tmp:
            result = ai_review.run(self.config, [self.url], None, client, Path(tmp, "out.jsonl"))
            row = json.loads(Path(tmp, "out.jsonl").read_text())
        self.assertEqual(result["requests"], 0)
        self.assertEqual(opener.requests, [])
        self.assertTrue(any(x["kind"] == "sql_error" for x in row["test_candidates"]))

    @patch("ai_review.socket.getaddrinfo", return_value=[(None, None, None, None, ("93.184.216.34", 443))])
    @patch("ai_review.time.sleep")
    def test_model_selects_only_configured_probe_after_baseline(self, pause, dns):
        opener = Opener()
        client = ai_review.HttpClient(ai_review.Policy(self.config), {}, opener)
        with tempfile.TemporaryDirectory() as tmp:
            result = ai_review.run(self.config, [self.url], Planner(), client, Path(tmp, "out.jsonl"), live=True)
            row = json.loads(Path(tmp, "out.jsonl").read_text())
        self.assertEqual(result["requests"], 2)
        self.assertEqual([x.get_method() for x in opener.requests], ["GET", "GET"])
        self.assertIn("%27", opener.requests[1].full_url)
        self.assertEqual([x["action"] for x in row["observations"]], ["anonymous", "sql_error"])
        self.assertEqual(row["findings"], [])

    @patch("ai_review.socket.getaddrinfo", return_value=[(None, None, None, None, ("93.184.216.34", 443))])
    def test_upload_is_plain_text_with_fixed_endpoint(self, dns):
        url = "https://example.test/upload"
        self.config["active_tests"][url] = {"upload": {"field": "file"}}
        opener = Opener()
        client = ai_review.HttpClient(ai_review.Policy(self.config), {}, opener)
        obs, raw = client.configured_test(url, "upload", self.config["active_tests"][url]["upload"])
        request = opener.requests[0]
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(request.full_url, url)
        self.assertIn(b".txt", request.data)
        self.assertIn(b"Content-Type: text/plain", request.data)
        self.assertEqual(obs["action"], "upload")


if __name__ == "__main__":
    unittest.main()
