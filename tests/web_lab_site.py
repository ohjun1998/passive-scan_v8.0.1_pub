"""Ephemeral interactive web app for scanner integration tests.

Only binds loopback. Every run starts with synthetic users and data.
"""

import html
import hmac
import json
import secrets
import threading
from contextlib import contextmanager
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


OWNED_NOTE_MARKER = "ALICE_OWNED_LAB_NOTE_7F2C"


class LabState:
    def __init__(self):
        self.lock = threading.Lock()
        self.users = {"alice": "lab-alice", "bob": "lab-bob"}
        self.sessions = {}
        self.reset_tokens = {}
        self.posts = [{"id": 1, "author": "alice", "title": "Welcome",
                       "body": "Synthetic board post", "comments": [
                           {"author": "bob", "body": "First lab comment"}]}]


class Handler(BaseHTTPRequestHandler):
    server_version = "PassiveScanLab/1.0"

    def log_message(self, *_args):
        pass

    def send(self, code, body, content_type="text/html; charset=utf-8", extra=None):
        payload = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for name, value in (extra or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(payload)

    def page(self, title, content, code=200, extra=None):
        shell = ('<!doctype html><html lang="ko"><meta charset="utf-8">'
                 '<title>Passive Scan Lab · ' + html.escape(title) + '</title>'
                 '<body><nav><a href="/">Home</a> · <a href="/login">Login</a> · '
                 '<a href="/forgot-password">Password help</a> · '
                 '<a href="/board">Board</a> · <a href="/search?q=lab">Search</a></nav>'
                 '<main><h1>' + html.escape(title) + '</h1>' + content + '</main></body></html>')
        self.send(code, shell, extra=extra)

    def current_user(self):
        jar = cookies.SimpleCookie()
        try:
            jar.load(self.headers.get("Cookie", ""))
            sid = jar["lab_session"].value if "lab_session" in jar else ""
        except cookies.CookieError:
            return None
        with self.server.lab.lock:
            return self.server.lab.sessions.get(sid)

    def form(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length < 0 or length > 4096:
            raise ValueError("Invalid form size")
        return {key: values[0] for key, values in
                parse_qs(self.rfile.read(length).decode("utf-8"), keep_blank_values=True).items()}

    def do_GET(self):
        parts = urlsplit(self.path)
        path = parts.path
        if path == "/":
            return self.page("Test site", "<p>Local synthetic login, recovery, board and comments.</p>")
        if path == "/login":
            return self.page("Login", '<form method="post" action="/login">'
                             '<input name="username" autocomplete="username" required>'
                             '<input name="password" type="password" required>'
                             '<button>Sign in</button></form>')
        if path == "/forgot-password":
            return self.page("Password help", '<form method="post" action="/forgot-password">'
                             '<input name="username" required><button>Request reset</button></form>')
        if path == "/reset-password":
            token = html.escape(parse_qs(parts.query).get("token", [""])[0], quote=True)
            return self.page("Reset password", '<form method="post" action="/reset-password">'
                             f'<input type="hidden" name="token" value="{token}">'
                             '<input name="password" type="password" required>'
                             '<button>Reset</button></form>')
        if path == "/board":
            with self.server.lab.lock:
                posts = [(p["id"], p["title"]) for p in self.server.lab.posts]
            links = "".join(f'<li><a href="/board/{pid}">{html.escape(title)}</a></li>'
                            for pid, title in posts)
            return self.page("Board", '<ul>' + links + '</ul><form method="post" action="/board/new">'
                             '<input name="title" required><textarea name="body"></textarea>'
                             '<button>Post</button></form>')
        if path.startswith("/board/") and path.count("/") == 2:
            try:
                pid = int(path.split("/")[-1])
            except ValueError:
                return self.page("Not found", "", 404)
            with self.server.lab.lock:
                post = next((p.copy() for p in self.server.lab.posts if p["id"] == pid), None)
            if not post:
                return self.page("Not found", "", 404)
            comments = "".join(f'<li>{html.escape(c["author"])}: {html.escape(c["body"])}</li>'
                               for c in post["comments"])
            return self.page(post["title"], '<p>' + html.escape(post["body"]) +
                             '</p><h2>Comments</h2><ul>' + comments + '</ul>'
                             f'<form method="post" action="/board/{pid}/comments">'
                             '<textarea name="body" required></textarea><button>Comment</button></form>')
        if path == "/search":
            query = parse_qs(parts.query).get("q", [""])[0]
            return self.page("Search", '<form><input name="q"><button>Search</button></form>'
                             '<p>Results for ' + html.escape(query) + '</p>')
        if path == "/lab/private-note":
            # Deliberately vulnerable, isolated fixture: Bob can retrieve Alice's
            # synthetic note. Never use this route outside the loopback lab.
            bearer = self.headers.get("Authorization", "")
            if bearer not in ("Bearer lab-account-a", "Bearer lab-account-b"):
                return self.send(401, '{"error":"authentication required"}',
                                 "application/json")
            if parse_qs(parts.query).get("id") != ["1"]:
                return self.send(404, '{"error":"note not found"}', "application/json")
            return self.send(200, json.dumps({"id": 1, "owner": "alice",
                                              "note": OWNED_NOTE_MARKER}),
                             "application/json")
        return self.page("Not found", "", 404)

    def do_POST(self):
        try:
            form = self.form()
        except (ValueError, UnicodeError):
            return self.page("Invalid request", "", 400)
        path = urlsplit(self.path).path
        state = self.server.lab
        if path == "/login":
            username = form.get("username", "")
            password = form.get("password", "")
            if username not in state.users or not hmac.compare_digest(
                    state.users[username], password):
                return self.page("Login failed", "Invalid credentials", 401)
            sid = secrets.token_urlsafe(24)
            with state.lock:
                state.sessions[sid] = username
            return self.page("Signed in", html.escape(username), extra={
                "Set-Cookie": f"lab_session={sid}; HttpOnly; SameSite=Lax; Path=/"})
        if path == "/forgot-password":
            username = form.get("username", "")
            if username in state.users:
                with state.lock:
                    state.reset_tokens[secrets.token_urlsafe(20)] = username
            return self.page("Password help", "If the account exists, a reset was requested.")
        if path == "/reset-password":
            token = form.get("token", "")
            password = form.get("password", "")
            if not password or len(password) > 128:
                return self.page("Invalid password", "", 400)
            with state.lock:
                username = state.reset_tokens.pop(token, None)
                if username:
                    state.users[username] = password
            return self.page("Reset password", "Updated" if username else "Invalid token",
                             200 if username else 400)
        if path == "/board/new":
            username = self.current_user()
            if not username:
                return self.page("Sign in required", "", 401)
            title, body = form.get("title", "")[:120], form.get("body", "")[:1000]
            if not title:
                return self.page("Title required", "", 400)
            with state.lock:
                pid = len(state.posts) + 1
                state.posts.append({"id": pid, "author": username, "title": title,
                                    "body": body, "comments": []})
            return self.page("Post created", f'<a href="/board/{pid}">View post</a>', 201)
        if path.startswith("/board/") and path.endswith("/comments"):
            username = self.current_user()
            if not username:
                return self.page("Sign in required", "", 401)
            try:
                pid = int(path.split("/")[2])
            except ValueError:
                return self.page("Not found", "", 404)
            with state.lock:
                post = next((p for p in state.posts if p["id"] == pid), None)
                if post:
                    post["comments"].append({"author": username, "body": form.get("body", "")[:1000]})
            return self.page("Comment added", "Saved" if post else "Not found",
                             201 if post else 404)
        return self.page("Not found", "", 404)


@contextmanager
def serve():
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.lab = LabState()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
