"""Optional bounded production probe: at most 20 sequential HTTPS HEAD requests."""

import argparse
import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def probe(input_file, output_file, opener=None, pause=time.sleep):
    opener = opener or urllib.request.build_opener(NoRedirect)
    roots = input_file.read_text(encoding="utf-8").splitlines()
    if len(roots) > 20 or len(set(roots)) != len(roots):
        raise ValueError("Probe budget exceeded or duplicate origins")
    for root in roots:
        parts = urlsplit(root)
        if (parts.scheme != "https" or not parts.hostname or
                parts.username or parts.password or parts.port not in (None, 443) or
                parts.path != "/" or parts.query or parts.fragment or
                root != f"https://{parts.hostname}/"):
            raise ValueError("Only plain HTTPS origins are permitted")

    output_file.parent.mkdir(parents=True, exist_ok=True)
    with output_file.open("w", encoding="utf-8") as output:
        for index, root in enumerate(roots):
            if index:
                pause(2)
            request = urllib.request.Request(
                root, method="HEAD", headers={"User-Agent": "PassiveScan-v8.0.1-bounded-probe/1.0"}
            )
            try:
                with opener.open(request, timeout=5) as response:
                    status = response.status
            except urllib.error.HTTPError as error:
                # Redirects are returned here by NoRedirect, never followed.
                status = error.code
            except (urllib.error.URLError, TimeoutError, OSError) as error:
                print(f"HEAD probe failed for {root}: {type(error).__name__}")
                continue
            output.write(json.dumps({"url": root, "status_code": status}) + "\n")
            output.flush()
            if status == 429 or 500 <= status <= 599:
                print(f"Stopping after HTTP {status} from {root}")
                break


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--confirm-production-probe", action="store_true")
    args = parser.parse_args()
    if not args.confirm_production_probe:
        parser.error("Explicit --confirm-production-probe is required")
    probe(args.input, args.output)
