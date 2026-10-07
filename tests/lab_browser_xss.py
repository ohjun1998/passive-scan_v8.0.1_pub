#!/usr/bin/env python3
"""Real Chromium check using only mocked HTTP responses; no target network."""

import html
import sys
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ai_review


class Response:
    status = 200
    headers = {"Content-Type": "text/html; charset=utf-8"}

    def __init__(self, body):
        self.body = body

    def read(self, limit):
        return self.body[:limit]

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


class MockOpener:
    def __init__(self, escape_output):
        self.escape_output = escape_output

    def open(self, request, timeout):
        value = parse_qs(urlsplit(request.full_url).query)["q"][0]
        if self.escape_output:
            value = html.escape(value)
        return Response(f"<!doctype html><html><body>{value}</body></html>".encode())


def main():
    url = "https://example.test/search?q=plain"
    config = {"allowed_hosts": ["example.test"], "live_path_prefixes": ["/search"],
              "max_http_requests": 1, "min_seconds_per_host": 1}
    with patch("ai_review.socket.getaddrinfo",
               return_value=[(None, None, None, None, ("93.184.216.34", 443))]):
        results = []
        for escaped in (False, True):
            client = ai_review.HttpClient(ai_review.Policy(config), {}, MockOpener(escaped))
            observation, _ = client.configured_test(url, "xss_browser", {"parameter": "q"})
            results.append(observation["script_executed"])
    assert results == [True, False], results
    print("Captured HTML: executable canary observed; escaped response did not execute")


if __name__ == "__main__":
    main()
