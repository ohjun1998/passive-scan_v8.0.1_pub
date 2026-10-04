"""Local Sign in with ChatGPT for the optional bounded reviewer."""

import base64
import hashlib
import json
import os
import secrets
import stat
import tempfile
import time
import urllib.parse
import urllib.request
import uuid
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

AUTH = "https://auth.openai.com"
RESOURCE = "https://api.openai.com/v1"
SCOPES = "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct"
CONFIG_DIR = Path.home() / ".config" / "passive-scan-review"


def _b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _request_json(url, data=None, headers=None):
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    request = urllib.request.Request(url, body, headers=headers or {})
    with urllib.request.urlopen(request, timeout=15) as response:
        return json.load(response)


def _write_private(path, value):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.parent.is_symlink() or path.is_symlink():
        raise RuntimeError("Credential path must not be a symlink")
    os.chmod(path.parent, 0o700)
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=".session-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(value, stream)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def _read_private(path):
    if path.is_symlink() or (path.exists() and stat.S_IMODE(path.stat().st_mode) & 0o077):
        raise RuntimeError("Credential file permissions must be owner-only (0600)")
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def _verify_id_token(token, client_id, nonce):
    """Check RS256 signature and OIDC claims using the issuer's current JWKS."""
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.hazmat.primitives import hashes

    header64, payload64, signature64 = token.split(".")
    decode = lambda item: base64.urlsafe_b64decode(item + "=" * (-len(item) % 4))
    header = json.loads(decode(header64))
    if header.get("alg") != "RS256" or not header.get("kid"):
        raise RuntimeError("Unexpected ID token algorithm")
    discovery = _request_json(AUTH + "/.well-known/openid-configuration")
    jwks_uri = discovery["jwks_uri"]
    if not jwks_uri.startswith(AUTH + "/"):
        raise RuntimeError("Unexpected JWKS endpoint")
    keys = _request_json(jwks_uri)["keys"]
    key = next((k for k in keys if k.get("kid") == header["kid"] and k.get("kty") == "RSA"
                and k.get("use", "sig") == "sig"), None)
    if key is None:
        raise RuntimeError("ID token signing key unavailable")
    number = lambda value: int.from_bytes(decode(value), "big")
    public = rsa.RSAPublicNumbers(number(key["e"]), number(key["n"])).public_key()
    public.verify(decode(signature64), f"{header64}.{payload64}".encode(), padding.PKCS1v15(), hashes.SHA256())
    claims = json.loads(decode(payload64))
    if (claims.get("iss") != AUTH or claims.get("aud") != client_id
            or claims.get("nonce") != nonce or not claims.get("sub")
            or not isinstance(claims.get("exp"), (int, float)) or claims["exp"] <= time.time()
            or claims.get("nbf", 0) > time.time() + 60):
        raise RuntimeError("ID token claims did not match this sign-in")
    return claims


class ChatGPTSession:
    def __init__(self, directory=CONFIG_DIR):
        self.directory = Path(directory)
        self.host_file = self.directory / "host.json"
        self.session_file = self.directory / "session.json"

    def _host_id(self):
        saved = _read_private(self.host_file)
        if saved:
            return saved["host_id"]
        host_id = "urn:uuid:" + str(uuid.uuid4())
        _write_private(self.host_file, {"host_id": host_id})
        return host_id

    def sign_in(self, open_browser=webbrowser.open, timeout=180):
        saved = _read_private(self.session_file)
        host_id = self._host_id()
        state, nonce, verifier = (secrets.token_urlsafe(32) for _ in range(3))
        result = {}

        class Callback(BaseHTTPRequestHandler):
            def do_GET(self):
                if urllib.parse.urlsplit(self.path).path != "/auth/callback":
                    self.send_error(404)
                    return
                query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
                if query.get("state") != [state] or result:
                    self.send_error(400, "Invalid authorization state")
                    return
                result.update({key: values[0] for key, values in query.items() if values})
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.end_headers()
                self.wfile.write(b"Authorization received. You can close this tab.")

            def log_message(self, *_args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Callback)
        server.timeout = 1
        callback = f"http://127.0.0.1:{server.server_port}/auth/callback"
        client_id = saved["client_id"] if saved else "dynamic_agent_client"
        params = {
            "client_id": client_id, "ext_agent_host_id": host_id,
            "response_type": "code", "redirect_uri": callback, "scope": SCOPES,
            "resource": RESOURCE, "state": state, "nonce": nonce,
            "code_challenge_method": "S256",
            "code_challenge": _b64(hashlib.sha256(verifier.encode()).digest()),
        }
        if saved:
            if saved.get("id_token"):
                params["id_token_hint"] = saved["id_token"]
            if saved.get("email"):
                params["login_hint"] = saved["email"]
        else:
            params["agent_name_hint"] = "Passive Scan Review"
        url = AUTH + "/api/accounts/authorize?" + urllib.parse.urlencode(params)
        try:
            if not open_browser(url):
                raise RuntimeError("Open the sign-in link in the browser on this same computer")
            deadline = time.monotonic() + timeout
            while not result and time.monotonic() < deadline:
                server.handle_request()
        finally:
            server.server_close()
        if not result:
            raise RuntimeError("ChatGPT authorization timed out")
        if result.get("error"):
            raise RuntimeError("ChatGPT authorization declined")
        issued = result.get("client_id", client_id)
        if (not result.get("code") or issued == "dynamic_agent_client"
                or (saved and issued != saved["client_id"])):
            raise RuntimeError("ChatGPT client registration was incomplete")
        token = _request_json(AUTH + "/api/accounts/oauth/token", {
            "grant_type": "authorization_code", "client_id": issued,
            "code": result["code"], "code_verifier": verifier,
            "redirect_uri": callback, "resource": RESOURCE,
        })
        claims = _verify_id_token(token["id_token"], issued, nonce)
        if saved and claims["sub"] != saved["subject"]:
            raise RuntimeError("A different ChatGPT account was selected")
        if "chatgpt.tokens.use.direct" not in token.get("scope", "").split():
            raise RuntimeError("ChatGPT plan permission was not granted")
        if token.get("token_type", "").lower() != "bearer" or not token.get("refresh_token"):
            raise RuntimeError("Missing renewable bearer credentials")
        record = dict(token, client_id=issued, subject=claims["sub"],
                      email=claims.get("email", ""), host_id=host_id,
                      expires_at=time.time() + int(token["expires_in"]))
        _write_private(self.session_file, record)
        return {"email": record["email"], "client_id": issued, "sharing": True}

    def access_token(self):
        # Serialize rotating refresh tokens across local processes.
        import fcntl
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        lock_path = self.directory / "refresh.lock"
        if lock_path.is_symlink():
            raise RuntimeError("Credential lock path must not be a symlink")
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        with os.fdopen(fd, "w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            saved = _read_private(self.session_file)
            if not saved:
                raise RuntimeError("Run chatgpt_auth.py login on this computer first")
            if "chatgpt.tokens.use.direct" not in saved.get("scope", "").split():
                raise RuntimeError("ChatGPT plan permission is unavailable")
            if saved["expires_at"] <= time.time() + 120:
                updated = _request_json(AUTH + "/api/accounts/oauth/token", {
                    "grant_type": "refresh_token", "client_id": saved["client_id"],
                    "refresh_token": saved["refresh_token"], "resource": RESOURCE,
                })
                if not updated.get("refresh_token") or not updated.get("access_token"):
                    raise RuntimeError("Renewed credentials are incomplete")
                saved.update(updated)
                saved["expires_at"] = time.time() + int(updated["expires_in"])
                _write_private(self.session_file, saved)
            return saved["access_token"]

    def models(self):
        data = _request_json(RESOURCE + "/models", headers={
            "Authorization": "Bearer " + self.access_token()})
        return [model["slug"] for model in data.get("models", [])
                if model.get("visibility") == "list" and model.get("slug")]


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Local ChatGPT plan connection")
    parser.add_argument("command", choices=["login", "models"])
    args = parser.parse_args()
    session = ChatGPTSession()
    if args.command == "login":
        print(json.dumps(session.sign_in()))
    else:
        print("\n".join(session.models()))
