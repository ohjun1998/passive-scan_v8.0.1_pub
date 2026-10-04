import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import ai_review


class FakeResponse:
    def __init__(self, status, body):
        self.status = status
        self.body = body
        self.headers = {"Content-Type": "application/json"}

    def read(self, limit):
        return self.body[:limit]

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class SequentialPlanner:
    def __init__(self, steps):
        self.steps = iter(steps)
        self.contexts = []

    def choose(self, url, available, observations):
        self.contexts.append(list(observations))
        action = next(self.steps)
        assert action in available or action == "stop"
        return {"action": action, "reason": "test"}


class AiReviewTests(unittest.TestCase):
    def setUp(self):
        self.url = "https://example.test/api/orders/123"
        self.config = {
            "allowed_hosts": ["example.test"], "max_urls": 2,
            "live_path_prefixes": ["/api/orders/", "/search"],
            "max_http_requests": 8, "min_seconds_per_host": 1,
            "expectations": {self.url: {"owner": "a", "private_marker": "OWN_TEST_MARKER",
                                            "other_account_must_be_denied": True}},
        }

    def test_dry_run_has_no_network_or_model_calls(self):
        policy = ai_review.Policy(self.config)
        client = ai_review.HttpClient(policy, {}, opener=Mock())
        planner = Mock()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory, "out.jsonl")
            result = ai_review.run(self.config, [self.url, "https://outside.test/"], planner, client, output)
            report = json.loads(output.read_text().strip())
        self.assertEqual(result["requests"], 0)
        self.assertEqual(report["state"], "dry_run")
        self.assertEqual(report["categories"], ["object_access"])
        planner.choose.assert_not_called()

    def test_repeated_id_routes_are_sampled_once(self):
        config = dict(self.config, max_urls=3)
        policy = ai_review.Policy(config)
        client = ai_review.HttpClient(policy, {}, opener=Mock())
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory, "out.jsonl")
            result = ai_review.run(config, [self.url, self.url.replace("123", "456")], None,
                                   client, output)
        self.assertEqual(result["candidates"], 1)

    def test_live_uses_http_observations_to_choose_next_action_and_flags_own_marker(self):
        planner = SequentialPlanner(["a", "b", "stop"])
        opener = Mock()
        opener.open.side_effect = [FakeResponse(200, b'{"order":"OWN_TEST_MARKER"}'),
                                   FakeResponse(200, b'{"order":"OWN_TEST_MARKER"}')]
        client = ai_review.HttpClient(ai_review.Policy(self.config), {"a": "secret-a", "b": "secret-b"}, opener)
        with tempfile.TemporaryDirectory() as directory, patch(
            "ai_review.socket.getaddrinfo", return_value=[(2, 1, 6, "", ("93.184.215.14", 443))]
        ), patch("ai_review.time.sleep"):
            output = Path(directory, "result.jsonl")
            result = ai_review.run(self.config, [self.url], planner, client, output, live=True)
            report = json.loads(output.read_text().strip())
        self.assertEqual(result["requests"], 2)
        self.assertTrue(planner.contexts[1][0]["marker_present"])
        self.assertEqual(report["findings"][0]["status"], "manual_review")
        self.assertNotIn("secret-a", json.dumps(report))
        self.assertEqual(opener.open.call_args_list[0].args[0].get_method(), "GET")

    def test_reflected_marker_is_only_candidate_not_xss(self):
        url = "https://example.test/search?q=old"
        policy = ai_review.Policy(self.config)
        opener = Mock()

        def reflected(request, timeout):
            value = dict(ai_review.urllib.parse.parse_qsl(ai_review.urllib.parse.urlsplit(request.full_url).query))["q"]
            return FakeResponse(200, f"Results: {value}".encode())

        opener.open.side_effect = reflected
        client = ai_review.HttpClient(policy, {}, opener)
        with patch("ai_review.socket.getaddrinfo", return_value=[(2, 1, 6, "", ("93.184.215.14", 443))]):
            observation, _ = client.fetch(url, reflection=True)
        finding = ai_review.assess([observation], {})[0]
        self.assertTrue(observation["marker_reflected"])
        self.assertEqual(finding["kind"], "reflected_input")
        self.assertEqual(finding["status"], "manual_review")

    def test_scope_redirect_and_stop_signal(self):
        policy = ai_review.Policy(self.config)
        for url in ("https://outside.test/", "https://example.test/logout", "http://example.test/",
                    "https://user:pass@example.test/", "https://example.test:8080/",
                    "https://example.test/api/orders/%2e%2e/logout"):
            with self.assertRaises(ValueError):
                policy.validate(url)
        self.assertIsNone(ai_review.NoRedirect().redirect_request(None, None, 302, "", {},
                                                                     "https://outside.test/"))
        planner = SequentialPlanner(["anonymous"])
        opener = Mock()
        opener.open.return_value = FakeResponse(503, b"Unavailable")
        client = ai_review.HttpClient(policy, {}, opener)
        with tempfile.TemporaryDirectory() as directory, patch(
            "ai_review.socket.getaddrinfo", return_value=[(2, 1, 6, "", ("93.184.215.14", 443))]
        ):
            output = Path(directory, "result.jsonl")
            ai_review.run(self.config, [self.url, "https://example.test/next"], planner, client, output, live=True)
            rows = output.read_text().splitlines()
        self.assertEqual(len(rows), 1)
        self.assertEqual(json.loads(rows[0])["state"], "halted_on_server_signal")
        self.assertEqual(opener.open.call_count, 1)

    def test_gpt_planner_only_accepts_preapproved_actions(self):
        fake_create = Mock(return_value=SimpleNamespace(output_text='{"action":"b","reason":"test"}'))
        fake_openai = SimpleNamespace(OpenAI=lambda: SimpleNamespace(
            responses=SimpleNamespace(create=fake_create)))
        with patch.dict("sys.modules", {"openai": fake_openai}):
            planner = ai_review.GptPlanner("test-model")
            result = planner.choose("https://example.test/search?q=private-value", ["anonymous"], [])
        self.assertEqual(result["action"], "stop")
        arguments = fake_create.call_args.kwargs
        self.assertNotIn("private-value", arguments["input"])
        self.assertFalse(arguments["store"])

    def test_response_preview_redacts_common_secrets(self):
        redacted = ai_review.sanitize('{"password":"hunter2","token":"abc123","email":"person@example.test"}')
        self.assertNotIn("hunter2", redacted)
        self.assertNotIn("abc123", redacted)
        self.assertNotIn("person@example.test", redacted)


if __name__ == "__main__":
    unittest.main()
