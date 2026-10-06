import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import ai_review
import review_report


class Response:
    status = 200
    headers = {"Content-Type": "application/json"}

    def read(self, limit):
        return b'{"note":"OWN_TEST_MARKER"}'[:limit]

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


class Opener:
    def __init__(self):
        self.requests = []

    def open(self, request, timeout):
        self.requests.append(request)
        return Response()


class GlobalPlanner:
    def __init__(self):
        self.contexts = []

    def choose_intent(self, situation, options):
        self.contexts.append(situation)
        assets = situation["assets"]
        order_id = next(asset["id"] for asset in assets if "/orders/" in asset["path"])
        step = len(self.contexts)
        action = {1: "a", 2: "b"}.get(step)
        if action is None:
            return {"intent_id": "stop", "reason": "Enough evidence for human review"}
        selected = f"{order_id}:{action}"
        assert selected in {key for key, _ in options}
        return {"intent_id": selected, "reason": "Compare owned test object between accounts"}


class GlobalPlanningTests(unittest.TestCase):
    @patch("ai_review.socket.getaddrinfo", return_value=[(None, None, None, None, ("93.184.216.34", 443))])
    @patch("ai_review.time.sleep")
    def test_prior_facts_and_finding_inform_the_next_intent(self, pause, dns):
        order = "https://example.test/api/orders/123"
        search = "https://example.test/search?q=shoes"
        config = {
            "allowed_hosts": ["example.test"],
            "live_path_prefixes": ["/api/orders/", "/search"],
            "max_urls": 3, "max_http_requests": 5, "max_planning_steps": 4,
            "min_seconds_per_host": 1, "enabled_test_kinds": ["access_control", "reflection"],
            "expectations": {order: {"owner": "a", "private_marker": "OWN_TEST_MARKER",
                                     "other_account_must_be_denied": True}},
        }
        opener = Opener()
        client = ai_review.HttpClient(ai_review.Policy(config),
                                      {"a": "test-a", "b": "test-b"}, opener)
        planner = GlobalPlanner()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory, "result.jsonl")
            result = ai_review.run(config, [order, search], planner, client, output, live=True)
            rows = [json.loads(line) for line in output.read_text().splitlines()]
        self.assertEqual(result["planning_mode"], "global_adaptive")
        self.assertEqual(result["requests"], 2)
        self.assertEqual(len(planner.contexts[0]["assets"]), 2)
        self.assertEqual(planner.contexts[0]["recent_facts"], [])
        self.assertEqual(len(planner.contexts[1]["recent_facts"]), 1)
        self.assertEqual(len(planner.contexts[2]["manual_review_candidates"]), 1)
        order_row = next(row for row in rows if row["url"] == order)
        search_row = next(row for row in rows if row["url"] == search)
        self.assertEqual([x["action"] for x in order_row["observations"]], ["a", "b"])
        self.assertEqual(order_row["findings"][0]["evidence_ids"], ["obs-1", "obs-2"])
        self.assertEqual(search_row["state"], "not_selected")
        self.assertEqual(rows[0]["planning_summary"]["steps"], 2)
        self.assertIn("계획에서 선택되지 않음", review_report.readable_html(rows))

    def test_unavailable_intent_cannot_execute(self):
        class InventingPlanner:
            def choose_intent(self, situation, options):
                return {"intent_id": "asset-1:delete", "reason": "invented"}

        url = "https://example.test/search?q=x"
        config = {"allowed_hosts": ["example.test"], "live_path_prefixes": ["/search"],
                  "max_http_requests": 2}
        opener = Opener()
        client = ai_review.HttpClient(ai_review.Policy(config), {}, opener)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory, "result.jsonl")
            result = ai_review.run(config, [url], InventingPlanner(), client, output, live=True)
            row = json.loads(output.read_text())
        self.assertEqual(result["requests"], 0)
        self.assertEqual(row["state"], "model_unavailable")
        self.assertEqual(opener.requests, [])


if __name__ == "__main__":
    unittest.main()
