import json
import tempfile
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from unittest.mock import patch

import ai_review
import adaptive_worker
import review_report


class Response:
    status = 200
    headers = {"Content-Type": "text/plain"}

    def __init__(self, body):
        self.body = body

    def read(self, limit):
        return self.body[:limit]

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


class Opener:
    def __init__(self):
        self.requests = []

    def open(self, request, timeout):
        self.requests.append(request)
        value = parse_qs(urlsplit(request.full_url).query).get("q", [""])[0]
        return Response(("observed:" + value).encode())


class Planner:
    def __init__(self):
        self.worker_contexts = []

    def choose_intent(self, situation, options):
        return {"intent_id": next(key for key, action in options if action == "investigate"),
                "reason": "Investigate this search flow"}

    def propose_step(self, situation):
        self.worker_contexts.append(situation)
        number = len(self.worker_contexts)
        if number <= 2:
            return {"kind": "request", "method": "GET", "identity": "anonymous",
                    "changes": [{"key": "q", "value": "'" if number == 1 else "plain"}],
                    "reason": "Compare a syntax marker with normal input",
                    "expected": "Check whether the response changes",
                    "lead_kind": "", "evidence_ids": []}
        return {"kind": "stop", "method": "GET", "identity": "anonymous",
                "changes": [], "reason": "The two responses differ; inspect context",
                "expected": "", "lead_kind": "response_difference",
                "evidence_ids": ["obs-1", "obs-2"]}


class WorkerTests(unittest.TestCase):
    def setUp(self):
        self.url = "https://example.test/search?q=base"
        self.config = {
            "allowed_hosts": ["example.test"], "live_path_prefixes": ["/search"],
            "max_urls": 1, "max_http_requests": 4, "max_planning_steps": 1,
            "min_seconds_per_host": 1, "enabled_test_kinds": ["investigate"],
            "worker_capabilities": {self.url: {"methods": ["GET"],
                                                "query_keys": ["q"],
                                                "identities": ["anonymous"],
                                                "max_steps": 3}},
        }

    @patch("ai_review.socket.getaddrinfo", return_value=[(None, None, None, None, ("93.184.216.34", 443))])
    @patch("ai_review.time.sleep")
    def test_worker_invents_bounded_sequence_and_cites_real_evidence(self, pause, dns):
        opener = Opener()
        client = ai_review.HttpClient(ai_review.Policy(self.config), {}, opener)
        planner = Planner()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory, "out.jsonl")
            result = ai_review.run(self.config, [self.url], planner, client, output, live=True)
            row = json.loads(output.read_text())
        self.assertEqual(result["requests"], 2)
        self.assertEqual(len(opener.requests), 2)
        self.assertEqual(len(planner.worker_contexts[1]["observations"]), 1)
        self.assertEqual(row["worker_leads"][0]["evidence_ids"], ["obs-1", "obs-2"])
        self.assertEqual(row["worker_leads"][0]["confidence"], "inferred")
        self.assertEqual(row["findings"], [])
        self.assertIn("Worker가 제안한 검토 후보", review_report.detail_section(row, 1, 1))

    @patch("ai_review.socket.getaddrinfo", return_value=[(None, None, None, None, ("93.184.216.34", 443))])
    def test_unapproved_fields_methods_and_external_values_do_not_send(self, dns):
        opener = Opener()
        client = ai_review.HttpClient(ai_review.Policy(self.config), {}, opener)
        cap = adaptive_worker.capabilities(self.config, self.url)
        for step in [
            {"method": "DELETE", "identity": "anonymous", "changes": []},
            {"method": "GET", "identity": "anonymous",
             "changes": [{"key": "admin", "value": "1"}]},
            {"method": "GET", "identity": "anonymous",
             "changes": [{"key": "q", "value": "https://outside.test/collect"}]},
        ]:
            with self.assertRaises(ValueError):
                adaptive_worker.execute_step(client, self.url, cap, step)
        self.assertEqual(opener.requests, [])
        self.assertEqual(client.policy.request_count, 0)

    @patch("ai_review.socket.getaddrinfo", return_value=[(None, None, None, None, ("93.184.216.34", 443))])
    def test_post_requires_exact_form_capability(self, dns):
        url = "https://example.test/search"
        self.config["worker_capabilities"][url] = {
            "methods": ["POST"], "form_fields": ["query"], "identities": ["anonymous"]}
        opener = Opener()
        client = ai_review.HttpClient(ai_review.Policy(self.config), {}, opener)
        cap = adaptive_worker.capabilities(self.config, url)
        result, raw = adaptive_worker.execute_step(
            client, url, cap, {"method": "POST", "identity": "anonymous",
                               "changes": [{"key": "query", "value": "test"}]})
        self.assertEqual(opener.requests[0].get_method(), "POST")
        self.assertEqual(opener.requests[0].data, b"query=test")
        self.assertEqual(result["action"], "worker_post")

    @patch("ai_review.socket.getaddrinfo", return_value=[(None, None, None, None, ("93.184.216.34", 443))])
    def test_duplicate_query_key_is_rejected_before_network(self, dns):
        url = "https://example.test/search?q=one&q=two"
        opener = Opener()
        client = ai_review.HttpClient(ai_review.Policy(self.config), {}, opener)
        with self.assertRaisesRegex(ValueError, "duplicate query key"):
            adaptive_worker.execute_step(client, url,
                adaptive_worker.capabilities(self.config, self.url),
                {"method": "GET", "identity": "anonymous",
                 "changes": [{"key": "q", "value": "new"}]})
        self.assertEqual(opener.requests, [])


if __name__ == "__main__":
    unittest.main()
