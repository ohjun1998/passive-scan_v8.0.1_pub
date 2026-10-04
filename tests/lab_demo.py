#!/usr/bin/env python3
"""Local-only HTTP lab for the bounded reviewer; never serves production data."""

import argparse
import json
import sqlite3
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ai_review


HOST = "127.0.0.1"
PORT = 18080
MARKER = "OWN_TEST_ORDER_MARKER"


class LabHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        url = urlsplit(self.path)
        if url.path == "/api/orders/123":
            token = self.headers.get("Authorization", "")
            if token in ("Bearer lab-account-a", "Bearer lab-account-b"):
                # Deliberate lab defect: account B can read A's test order.
                self.respond(200, {"owner": "a", "note": MARKER})
            else:
                self.respond(403, {"error": "forbidden"})
        elif url.path == "/search":
            # Deliberate lab behavior: a search term is reflected as plain JSON.
            self.respond(200, {"query": parse_qs(url.query).get("q", [""])[0]})
        else:
            self.respond(404, {"error": "not found"})

    def respond(self, status, data):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        pass


class LabPlanner:
    """Repeatable stand-in for GPT so the HTTP/result path can be tested offline."""

    def choose(self, url, available, observations):
        if "/api/orders/" in url:
            if "a" in available:
                action = "a"
            elif observations and observations[0].get("marker_present") and "b" in available:
                action = "b"
            else:
                action = "stop"
        else:
            action = "reflection" if "reflection" in available else "stop"
        return {"action": action, "reason": "Local lab demonstration"}


def run_lab(output, planner=None):
    order_url = f"http://{HOST}:{PORT}/api/orders/123"
    search_url = f"http://{HOST}:{PORT}/search?q=example"
    config = {
        "allowed_hosts": [HOST], "live_path_prefixes": ["/api/orders/", "/search"],
        "max_urls": 2, "max_http_requests": 4, "min_seconds_per_host": 1,
        "expectations": {order_url: {
            "owner": "a", "private_marker": MARKER, "other_account_must_be_denied": True
        }},
    }
    with tempfile.TemporaryDirectory() as tmp:
        db = Path(tmp) / "recon_history.db"
        with sqlite3.connect(db) as conn:
            conn.execute("CREATE TABLE master_urls (url TEXT PRIMARY KEY)")
            conn.executemany("INSERT INTO master_urls (url) VALUES (?)",
                             [(order_url,), (search_url,)])
        server = ThreadingHTTPServer((HOST, PORT), LabHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            policy = ai_review.Policy(config, allow_private_lab=True)
            client = ai_review.HttpClient(policy, {"a": "lab-account-a", "b": "lab-account-b"})
            summary = ai_review.run(config, ai_review.load_urls(config, db), planner or LabPlanner(),
                                    client, output, live=True)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
    rows = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
    if planner is None:
        assert summary["requests"] == 3, summary
        assert {item["kind"] for row in rows for item in row["findings"]} == {
            "access_control", "reflected_input"
        }, rows
    print(json.dumps({"summary": summary, "findings": [
        {"url": row["url"], "findings": row["findings"]} for row in rows
    ]}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("lab_review_results.jsonl"))
    parser.add_argument("--chatgpt", action="store_true", help="Use your local ChatGPT login instead of fixed lab decisions")
    args = parser.parse_args()
    run_lab(args.output, ai_review.ChatGPTPlanner() if args.chatgpt else None)
