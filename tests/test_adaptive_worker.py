import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
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
        self.brief_context = None

    def choose_intent(self, situation, options):
        return {"intent_id": next(key for key, action in options if action == "investigate"),
                "reason": "Investigate this search flow"}

    def draft_test_brief(self, situation):
        self.brief_context = situation
        return {"hypothesis": "The search endpoint treats special text differently",
                "procedure": "Compare a syntax marker and an ordinary value in q",
                "decision_rule": "Review differing status or response structure"}

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
        self.assertEqual(planner.brief_context["planner_direction"], "Investigate this search flow")
        self.assertEqual(planner.worker_contexts[0]["generated_test_brief"], row["test_brief"])
        self.assertIn("assets", planner.brief_context["shared_progress"])
        self.assertEqual(row["worker_leads"][0]["evidence_ids"], ["obs-1", "obs-2"])
        self.assertEqual(row["worker_leads"][0]["confidence"], "inferred")
        self.assertEqual(row["findings"], [])
        self.assertIn("Worker가 제안한 검토 후보", review_report.detail_section(row, 1, 1))
        self.assertIn("AI가 작성한 테스트 지시문", review_report.detail_section(row, 1, 1))

    @patch("ai_review.socket.getaddrinfo", return_value=[(None, None, None, None, ("93.184.216.34", 443))])
    @patch("ai_review.time.sleep")
    def test_owned_fixture_is_passed_and_empty_lead_is_not_reported(self, pause, dns):
        url = "https://example.test/search?id=1"
        self.config["worker_capabilities"][url] = {
            "methods": ["GET"], "query_keys": ["id"],
            "identities": ["a", "b"], "max_steps": 2}
        self.config["expectations"] = {url: {
            "owner": "a", "other_account_must_be_denied": True}}

        class CautiousPlanner(Planner):
            def propose_step(self, situation):
                self.worker_contexts.append(situation)
                if len(self.worker_contexts) == 1:
                    return {"kind": "request", "method": "GET", "identity": "a",
                            "changes": [{"key": "id", "value": "1"}],
                            "reason": "Owner baseline", "expected": "Own note"}
                return {"kind": "stop", "lead_kind": "", "reason": "Insufficient evidence",
                        "evidence_ids": ["obs-1"]}

        planner = CautiousPlanner()
        client = ai_review.HttpClient(ai_review.Policy(self.config), {"a": "fixture"}, Opener())
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory, "out.jsonl")
            ai_review.run(self.config, [url], planner, client, output, live=True)
            row = json.loads(output.read_text())
        expected = {"id": "1", "owner_identity": "a",
                    "other_account_must_be_denied": True}
        self.assertEqual(planner.brief_context["owned_test_object"], expected)
        self.assertEqual(planner.worker_contexts[0]["owned_test_object"], expected)
        self.assertNotIn("worker_leads", row)

    def test_malformed_generated_brief_fails_closed(self):
        for brief in ({"hypothesis": "x"},
                      {"hypothesis": "x", "procedure": "", "decision_rule": "z"}):
            with self.assertRaises(ValueError):
                adaptive_worker.validate_brief(brief)
        self.assertEqual(len(adaptive_worker.validate_brief({
            "hypothesis": "x", "procedure": "y", "decision_rule": "z" * 501
        })["decision_rule"]), 500)

    def test_owned_access_candidate_needs_matching_test_marker_and_identity(self):
        expectation = {"owner": "a", "private_marker": "OWNED_FIXTURE",
                       "other_account_must_be_denied": True}
        a = {"action": "worker_get", "status": 200, "identity": "a",
             "request_fields": [{"key": "id", "value": "1"}],
             "body_sha256": "same", "owned_marker_present": True}
        b = {**a, "identity": "b"}
        lead = adaptive_worker.owned_access_candidate([a, b], expectation)
        self.assertEqual(lead["evidence_ids"], ["obs-1", "obs-2"])
        self.assertEqual(lead["confidence"], "observed")
        self.assertIsNone(adaptive_worker.owned_access_candidate(
            [a, {**b, "owned_marker_present": False}], expectation))
        self.assertIsNone(adaptive_worker.owned_access_candidate(
            [a, {**b, "request_fields": [{"key": "id", "value": "2"}]}], expectation))
        self.assertIsNone(adaptive_worker.owned_access_candidate(
            [a, {**b, "body_truncated": True}], expectation))

    def test_gpt_and_chatgpt_brief_calls_use_fixed_instructions(self):
        brief = {"hypothesis": "Compare response behavior",
                 "procedure": "Try two approved q values",
                 "decision_rule": "Inspect the observed difference"}
        gpt = ai_review.GptPlanner.__new__(ai_review.GptPlanner)
        gpt.model = "fixture"
        gpt_create = unittest.mock.Mock(return_value=SimpleNamespace(output_text=json.dumps(brief)))
        gpt.client = SimpleNamespace(responses=SimpleNamespace(create=gpt_create))
        self.assertEqual(gpt.draft_test_brief({"selected_asset": {"path": "/search"}}), brief)
        self.assertEqual(gpt_create.call_args.kwargs["text"]["format"]["name"],
                         "generated_test_brief")
        self.assertFalse(gpt_create.call_args.kwargs["store"])

        class Stream:
            def __enter__(self):
                return iter([SimpleNamespace(type="response.output_text.delta",
                                             delta=json.dumps(brief)),
                             SimpleNamespace(type="response.completed")])

            def __exit__(self, *_args):
                pass

        plus = ai_review.ChatGPTPlanner.__new__(ai_review.ChatGPTPlanner)
        plus.model = "fixture"
        plus.session = SimpleNamespace(access_token=lambda: "fixture-token")
        plus_create = unittest.mock.Mock(return_value=Stream())
        plus.OpenAI = lambda **_kwargs: SimpleNamespace(
            responses=SimpleNamespace(create=plus_create))
        self.assertEqual(plus.draft_test_brief({"selected_asset": {"path": "/search"}}), brief)
        self.assertTrue(plus_create.call_args.kwargs["stream"])
        self.assertFalse(plus_create.call_args.kwargs["store"])

        plus.reasoning_effort = "low"
        self.assertEqual(plus.draft_test_brief({"selected_asset": {"path": "/search"}}), brief)
        self.assertEqual(plus_create.call_args.kwargs["reasoning"], {"effort": "low"})
        self.assertEqual(plus_create.call_args.kwargs["max_output_tokens"], 1200)
        self.assertEqual(plus_create.call_args.kwargs["text"]["format"]["name"],
                         "generated_test_brief")

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
