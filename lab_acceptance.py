#!/usr/bin/env python3
"""Bounded acceptance check for the owned, synthetic Passive Scan web lab.

This intentionally creates one post and comment and resets Alice's demo password
back to its published demo value. It must never be pointed at another host.
"""

import http.cookiejar
import html
import json
import os
import urllib.error
import urllib.parse
import urllib.request
import uuid


BASE = "https://passive-scan-web-lab-ohjun.dhwns5555.chatgpt.site"
API = BASE + "/api/lab"
TIMEOUT = 10


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def client():
    return urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
        urllib.request.ProxyHandler({}),
        NoRedirect(),
    )


def call(opener, path, expected, data=None, origin=BASE):
    url = BASE + path
    if urllib.parse.urlsplit(url).hostname != urllib.parse.urlsplit(BASE).hostname:
        raise AssertionError("Request left the lab host")
    headers = {"Accept": "application/json"}
    if data is not None:
        headers.update({"Content-Type": "application/json", "Origin": origin})
    request = urllib.request.Request(
        url, data=json.dumps(data).encode() if data is not None else None,
        headers=headers, method="POST" if data is not None else "GET",
    )
    try:
        response = opener.open(request, timeout=TIMEOUT)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        if response.geturl().split("?")[0] != url.split("?")[0]:
            raise AssertionError("Unexpected redirect")
        body = response.read(65537)
        if len(body) > 65536:
            raise AssertionError("Unexpectedly large response")
        if response.status != expected:
            detail = body[:300].decode("utf-8", "replace") if data is None else ""
            raise AssertionError(f"{path.split('?')[0]}: expected {expected}, got {response.status}; "
                                 f"content-type={response.headers.get('Content-Type', '')}; "
                                 f"server={response.headers.get('Server', '')}; body={detail!r}")
        return json.loads(body) if "application/json" in response.headers.get("Content-Type", "") else body.decode()


def main():
    anonymous, alice, bob = client(), client(), client()
    checks = []

    def check(name, condition):
        if not condition:
            raise AssertionError(name)
        checks.append(name)

    check("anonymous session", call(anonymous, "/api/lab?op=session", 200)["user"] is None)
    check("public board", isinstance(call(anonymous, "/api/lab?op=board", 200), list))
    call(anonymous, "/api/lab?op=post", 401, {"title": "Denied", "body": "Denied"})
    call(anonymous, "/api/lab?op=comment", 401, {"postId": 1, "body": "Denied"})
    checks.append("anonymous writes denied")
    call(anonymous, "/api/lab?op=login", 401, {"username": "alice", "password": "wrong"})
    call(anonymous, "/api/lab?op=post", 403, {"title": "Denied", "body": "Denied"}, origin="https://example.invalid")
    checks.append("invalid credentials and cross-origin write denied")

    check("Alice login", call(alice, "/api/lab?op=login", 200,
                              {"username": "alice", "password": "lab-alice"})["user"] == "alice")
    check("Bob login", call(bob, "/api/lab?op=login", 200,
                            {"username": "bob", "password": "lab-bob"})["user"] == "bob")
    check("separate sessions", call(alice, "/api/lab?op=session", 200)["user"] == "alice"
          and call(bob, "/api/lab?op=session", 200)["user"] == "bob")

    marker = "acceptance-" + uuid.uuid4().hex[:12]
    created = call(alice, "/api/lab?op=post", 201,
                   {"title": marker, "body": "Synthetic acceptance post"})
    post_id = created["id"]
    check("post persisted", isinstance(post_id, int) and post_id > 1)
    call(bob, "/api/lab?op=comment", 201,
         {"postId": post_id, "body": "Synthetic acceptance comment"})
    post = call(anonymous, f"/api/lab?op=board&id={post_id}", 200)
    check("comment persisted", post["author"] == "alice" and post["title"] == marker
          and any(c["author"] == "bob" for c in post["comments"]))

    code = call(alice, "/api/lab?op=request-code", 200, {"username": "alice"})["code"]
    check("recovery code issued", isinstance(code, str) and len(code) == 8)
    call(alice, "/api/lab?op=reset", 200,
         {"username": "alice", "code": code, "password": "lab-alice"})
    check("reset invalidates session", call(alice, "/api/lab?op=session", 200)["user"] is None)
    call(alice, "/api/lab?op=reset", 400,
         {"username": "alice", "code": code, "password": "lab-alice"})
    checks.append("recovery code single use")
    check("login after recovery", call(alice, "/api/lab?op=login", 200,
                                       {"username": "alice", "password": "lab-alice"})["user"] == "alice")
    call(alice, "/api/lab?op=logout", 200, {})
    check("logout invalidates session", call(alice, "/api/lab?op=session", 200)["user"] is None)
    check("Bob session remains independent", call(bob, "/api/lab?op=session", 200)["user"] == "bob")
    call(bob, "/api/lab?op=logout", 200, {})

    reflected = call(anonymous, "/search?q=%3Cscript%3E", 200)
    check("search output escaped", html.escape("<script>") in reflected and "<script>" not in reflected)
    print(json.dumps({"lab": BASE, "checks_passed": len(checks), "checks": checks}, ensure_ascii=False))
    summary = os.getenv("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as file:
            file.write(f"## Synthetic lab acceptance\n\n{len(checks)} checks passed.\n\n")
            file.writelines(f"- {name}\n" for name in checks)


if __name__ == "__main__":
    main()
