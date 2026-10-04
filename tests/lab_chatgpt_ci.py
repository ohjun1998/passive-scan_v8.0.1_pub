#!/usr/bin/env python3
"""Manual GitHub-hosted lab using a short-lived ChatGPT access token only."""

import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ai_review
import chatgpt_auth
from lab_demo import run_lab


class OneShotSession:
    def __init__(self):
        self.token = os.environ.get("CHATGPT_CI_ACCESS_TOKEN", "")
        if not self.token:
            raise RuntimeError("CHATGPT_CI_ACCESS_TOKEN secret is missing; authorize locally and upload it first")

    def access_token(self):
        return self.token

    def models(self):
        data = chatgpt_auth._request_json(chatgpt_auth.RESOURCE + "/models", headers={
            "Authorization": "Bearer " + self.token})
        return [item["slug"] for item in data.get("models", [])
                if item.get("visibility") == "list" and item.get("slug")]


def main():
    planner = ai_review.ChatGPTPlanner(session=OneShotSession())
    print("ChatGPT model selected: " + planner.model, flush=True)
    with tempfile.TemporaryDirectory() as directory:
        output = Path(directory) / "lab_results.jsonl"
        run_lab(output, planner)
        rows = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
    if len(rows) != 2 or any(row["state"] != "completed" for row in rows):
        raise RuntimeError("Model-driven local lab did not complete; see per-URL states above")
    print("Live ChatGPT model -> bounded local HTTP lab: completed")


if __name__ == "__main__":
    main()
