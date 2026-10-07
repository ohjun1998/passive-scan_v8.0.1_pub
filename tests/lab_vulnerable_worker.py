#!/usr/bin/env python3
"""End-to-end adaptive Worker check against a deliberately flawed loopback route."""

import argparse
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ai_review
from web_lab_site import OWNED_NOTE_MARKER, serve


class MockGptResponses:
    """Reply through the real GptPlanner adapter without contacting OpenAI."""

    def __init__(self):
        self.calls = []

    def create(self, **request):
        assert request["store"] is False
        name = request["text"]["format"]["name"]
        context = json.loads(request["input"])
        self.calls.append(name)
        if name == "next_review_intent":
            choice = {"intent_id": next(item["id"] for item in context["available_intents"]
                                        if item["action"] == "investigate"),
                      "reason": "Compare access to Alice's own note as Alice and Bob"}
        elif name == "generated_test_brief":
            assert context["approved_capability"]["identities"] == ["a", "b"]
            choice = {"hypothesis": "A second account may read Alice's private note",
                      "procedure": "Request note 1 as owner A, then as account B",
                      "decision_rule": "Review if both responses contain the owned marker"}
        elif name == "worker_step":
            assert "private note" in context["generated_test_brief"]["hypothesis"]
            observations = context["observations"]
            if len(observations) < 2:
                choice = {"kind": "request", "method": "GET",
                          "identity": "a" if not observations else "b",
                          "changes": [{"key": "id", "value": "1"}],
                          "reason": "Compare owner and another test account",
                          "expected": "Owner marker should be withheld from account B",
                          "lead_kind": "", "evidence_ids": []}
            else:
                assert all(OWNED_NOTE_MARKER in item["preview"] for item in observations)
                choice = {"kind": "stop", "method": "GET", "identity": "a",
                          "changes": [], "reason": "Both accounts received the owned note marker",
                          "expected": "", "lead_kind": "access_control",
                          "evidence_ids": [item["evidence_id"] for item in observations]}
        else:
            raise AssertionError("Unexpected model call: " + name)
        return SimpleNamespace(output_text=json.dumps(choice))


def run_lab(output, auth="mock", model=None, reasoning_effort=None):
    with serve() as server:
        url = f"http://127.0.0.1:{server.server_port}/lab/private-note?id=1"
        config = {
            "allowed_hosts": ["127.0.0.1"],
            "live_path_prefixes": ["/lab/private-note"],
            "enabled_test_kinds": ["investigate"],
            "worker_capabilities": {url: {"methods": ["GET"],
                                          "query_keys": ["id"],
                                          "identities": ["a", "b"],
                                          "max_steps": 3}},
            "max_urls": 1, "max_http_requests": 3,
            "max_planning_steps": 1, "min_seconds_per_host": 1,
        }
        mock = None
        if auth == "mock":
            mock = MockGptResponses()
            planner = ai_review.GptPlanner.__new__(ai_review.GptPlanner)
            planner.model = "local-fixture"
            planner.client = SimpleNamespace(responses=mock)
        elif auth == "gpt":
            planner = ai_review.GptPlanner(model or config.get("model", "gpt-5.4"))
        else:
            from chatgpt_auth import ChatGPTSession
            session_dir = os.environ.get("CHATGPT_CI_SESSION_DIR")
            planner = ai_review.ChatGPTPlanner(
                model=model, session=ChatGPTSession(session_dir) if session_dir else ChatGPTSession(),
                reasoning_effort=reasoning_effort)
        policy = ai_review.Policy(config, allow_private_lab=True)
        client = ai_review.HttpClient(policy,
                                      {"a": "lab-account-a", "b": "lab-account-b"})
        summary = ai_review.run(config, [url], planner, client, output, live=True)
    rows = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
    if auth == "mock":
        assert mock.calls == ["next_review_intent", "generated_test_brief",
                              "worker_step", "worker_step", "worker_step"], mock.calls
        assert summary["requests"] == 2, summary
        row = rows[0]
        assert row["state"] == "completed", row
        assert row["test_brief"]["hypothesis"], row
        assert [item["identity"] for item in row["observations"]] == ["a", "b"], row
        assert all(item["status"] == 200 and OWNED_NOTE_MARKER in item["preview"]
                   for item in row["observations"]), row
        assert row["worker_leads"][0]["evidence_ids"] == ["obs-1", "obs-2"], row
        assert row["worker_leads"][0]["confidence"] == "inferred", row
        assert row["findings"] == [], row
    print(json.dumps({"mode": auth, "requests": summary["requests"],
                      "state": rows[0]["state"],
                      "generated_brief": rows[0].get("test_brief"),
                      "worker_leads": rows[0].get("worker_leads", [])},
                     ensure_ascii=False, indent=2))
    return summary, rows


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--auth", choices=("mock", "gpt", "chatgpt"), default="mock")
    parser.add_argument("--model")
    parser.add_argument("--reasoning-effort", choices=("low",))
    parser.add_argument("--output", type=Path, default=Path("/tmp/lab_vulnerable_worker.jsonl"))
    args = parser.parse_args()
    run_lab(args.output, args.auth, args.model, args.reasoning_effort)
