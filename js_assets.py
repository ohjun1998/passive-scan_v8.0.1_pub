#!/usr/bin/env python3
"""Download in-scope JavaScript without losing URL or version provenance."""
import hashlib
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urlsplit

MAX_BYTES = 2 * 1024 * 1024
MAX_FILES = 1000


def allowed(url, hosts):
    try:
        parsed = urlsplit(url)
        return (parsed.scheme in ("http", "https") and parsed.hostname in hosts
                and not parsed.username and not parsed.password
                and parsed.path.lower().endswith((".js", ".mjs")))
    except ValueError:
        return False


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def download(url, hosts, directory, opener):
    if not allowed(url, hosts):
        return None
    try:
        with opener.open(urllib.request.Request(url, headers={"User-Agent": "PassiveRecon/8.0.1", "Accept-Encoding": "identity"}), timeout=8) as response:
            kind = response.headers.get("Content-Type", "").lower()
            if "html" in kind:
                return None
            body = response.read(MAX_BYTES + 1)
            if len(body) > MAX_BYTES or body.lstrip().lower().startswith((b"<!doctype html", b"<html")):
                return None
        url_hash = hashlib.sha256(url.encode()).hexdigest()
        body_hash = hashlib.sha256(body).hexdigest()
        filename = f"{url_hash}_{body_hash}.js"
        (directory / filename).write_bytes(body)
        return filename, url
    except (urllib.error.URLError, OSError, ValueError):
        return None


def main(source, destination, mapping):
    directory = Path(destination)
    directory.mkdir(parents=True, exist_ok=True)
    hosts = {line.strip().split(":", 1)[-1].lower() for line in Path("targets.txt").read_text().splitlines() if line.strip()}
    urls = list(dict.fromkeys(Path(source).read_text().splitlines()))
    opener = urllib.request.build_opener(NoRedirect())
    with ThreadPoolExecutor(max_workers=10) as pool:
        records = list(pool.map(lambda url: download(url, hosts, directory, opener), urls[:MAX_FILES]))
    Path(mapping).write_text("".join(f"{name}\t{url}\n" for item in records if item for name, url in [item]), encoding="utf-8")
    print(f"JS: {sum(item is not None for item in records)} downloaded; {max(len(urls) - MAX_FILES, 0)} deferred")


if __name__ == "__main__":
    main(*sys.argv[1:])
