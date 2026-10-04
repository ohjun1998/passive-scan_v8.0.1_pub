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
    def __init__(self, action):
        encoded = json.dumps({"action": action, "reason": "CI fixture"})
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
        available = context["available_actions"]
        observations = context["observations"]
        self.calls += 1
        if "/api/orders/" in context["url_features"]["path"]:
            if "a" in available:
                action = "a"
            elif observations and observations[0].get("marker_present") and "b" in available:
                action = "b"
            else:
                action = "stop"
        else:
            action = "reflection" if "reflection" in available else "stop"
        return FakeStream(action)


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
    assert responses.calls == 5, responses.calls
    assert [row["state"] for row in rows] == ["completed", "completed"], rows
    assert {finding["kind"] for row in rows for finding in row["findings"]} == {
        "access_control", "reflected_input"
    }, rows
    assert sum(len(row["observations"]) for row in rows) == 3, rows
    print("ChatGPT planner stream -> bounded local HTTP -> findings: passed")


if __name__ == "__main__":
    main()
