#!/usr/bin/env python3
"""Exercise the ChatGPT planner and real local HTTP lab in GitHub Actions."""

import json
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ai_review
from lab_demo import run_lab


class FakeStream:
    def __init__(self, intent_id):
        encoded = json.dumps({"intent_id": intent_id, "reason": "CI fixture"})
        midpoint = len(encoded) // 2
        self.events = [SimpleNamespace(type="response.output_text.delta", delta=encoded[:midpoint]),
                       SimpleNamespace(type="response.output_text.delta", delta=encoded[midpoint:]),
                       SimpleNamespace(type="response.completed")]

    def __enter__(self):
        return iter(self.events)

    def __exit__(self, *_args):
        return False


class FakeResponses:
    def __init__(self):
        self.calls = 0

    def create(self, **request):
        assert request["store"] is False and request["stream"] is True
        context = json.loads(request["input"][0]["content"])
        available = {item["id"] for item in context["available_intents"]}
        order = next(asset["id"] for asset in context["assets"]
                     if "/api/orders/" in asset["path"])
        search = next(asset["id"] for asset in context["assets"]
                      if asset["path"] == "/search")
        self.calls += 1
        if f"{order}:a" in available:
            intent_id = f"{order}:a"
        elif f"{order}:b" in available and any(
                fact["asset_id"] == order and fact["test_marker_present"]
                for fact in context["recent_facts"]):
            intent_id = f"{order}:b"
        elif f"{search}:reflection" in available and context["manual_review_candidates"]:
            intent_id = f"{search}:reflection"
        else:
            intent_id = "stop"
        return FakeStream(intent_id)


def main():
    responses = FakeResponses()
    planner = ai_review.ChatGPTPlanner.__new__(ai_review.ChatGPTPlanner)
    planner.model = "ci-fixture-model"
    planner.session = SimpleNamespace(access_token=lambda: "ci-only-placeholder")
    planner.OpenAI = lambda **kwargs: SimpleNamespace(responses=responses)
    with tempfile.TemporaryDirectory() as directory:
        output = Path(directory) / "lab_results.jsonl"
        run_lab(output, planner)
        rows = [json.loads(line) for line in output.read_text().splitlines()]
    assert responses.calls == 4, responses.calls
    assert [row["state"] for row in rows] == ["completed", "completed"], rows
    assert {finding["kind"] for row in rows for finding in row["findings"]} == {
        "access_control", "reflected_input"
    }, rows
    assert sum(len(row["observations"]) for row in rows) == 3, rows
    print("ChatGPT planner stream -> bounded local HTTP -> findings: passed")


if __name__ == "__main__":
    main()
