#!/usr/bin/env python3
"""Exercise an interactive loopback site, then review its discovered GET URLs."""

import argparse
import http.cookiejar
import json
import os
import sqlite3
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ai_review
from web_lab_site import serve


class ReadOnlyPlanner:
    def choose(self, url, available, observations):
        action = ("reflection" if "reflection" in available else "anonymous")
        return {"action": action, "reason": "Deterministic local site check"}


def post(opener, base, path, fields):
    body = urllib.parse.urlencode(fields).encode()
    return opener.open(urllib.request.Request(base + path, data=body, method="POST"),
                       timeout=5).read().decode()


def run_lab(output, planner=None):
    with serve() as server, tempfile.TemporaryDirectory() as directory:
        base = f"http://127.0.0.1:{server.server_port}"
        alice = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
            urllib.request.ProxyHandler({}))
        bob = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
            urllib.request.ProxyHandler({}))

        assert "Signed in" in post(alice, base, "/login",
                                   {"username": "alice", "password": "lab-alice"})
        assert "reset was requested" in post(bob, base, "/forgot-password",
                                             {"username": "bob"})
        with server.lab.lock:
            token = next(key for key, user in server.lab.reset_tokens.items() if user == "bob")
        assert "Updated" in post(bob, base, "/reset-password",
                                 {"token": token, "password": "new-lab-bob"})
        assert "Signed in" in post(bob, base, "/login",
                                   {"username": "bob", "password": "new-lab-bob"})
        assert "Post created" in post(alice, base, "/board/new",
                                      {"title": "Lab <post>", "body": "Synthetic note"})
        assert "Comment added" in post(bob, base, "/board/2/comments",
                                       {"body": "Hello <lab>"})
        board = alice.open(base + "/board/2", timeout=5).read().decode()
        assert "Hello &lt;lab&gt;" in board and "Lab &lt;post&gt;" in board

        paths = ["/login", "/forgot-password", "/board", "/board/2",
                 "/search?q=sample"]
        db = Path(directory) / "recon_history.db"
        with sqlite3.connect(db) as conn:
            conn.execute("CREATE TABLE master_urls (url TEXT PRIMARY KEY)")
            conn.executemany("INSERT INTO master_urls (url) VALUES (?)",
                             [(base + path,) for path in paths])
        config = {"allowed_hosts": ["127.0.0.1"], "live_path_prefixes": ["/"],
                  "max_urls": 5, "max_http_requests": 5, "min_seconds_per_host": 1}
        policy = ai_review.Policy(config, allow_private_lab=True)
        session_dir = os.environ.get("CHATGPT_CI_SESSION_DIR")
        active_planner = planner
        if active_planner is None:
            active_planner = ReadOnlyPlanner()
        summary = ai_review.run(config, ai_review.load_urls(config, db),
                                active_planner, ai_review.HttpClient(policy, {}),
                                output, live=True)
    rows = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
    if len(rows) != 5 or any(row["state"] not in ("completed", "halted_on_server_signal")
                             for row in rows):
        raise RuntimeError("Interactive lab review did not complete: " +
                           json.dumps({"summary": summary, "states": [
                               (row["url"], row["state"], row.get("error")) for row in rows]}))
    if planner is None and summary["requests"] != 5:
        raise RuntimeError("Expected one real GET per discovered candidate")
    print(json.dumps({"site": "loopback-only", "features": [
        "login", "password reset", "board", "comments", "search"],
        "candidates": summary["candidates"], "http_requests": summary["requests"],
        "states": [row["state"] for row in rows]}, ensure_ascii=False))
    return summary, rows


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--chatgpt", action="store_true")
    parser.add_argument("--output", type=Path, default=Path("/tmp/web_lab_results.jsonl"))
    args = parser.parse_args()
    planner = None
    if args.chatgpt:
        from chatgpt_auth import ChatGPTSession
        planner = ai_review.ChatGPTPlanner(session=ChatGPTSession(
            os.environ["CHATGPT_CI_SESSION_DIR"]))
    run_lab(args.output, planner)
