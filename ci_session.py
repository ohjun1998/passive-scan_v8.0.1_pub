"""Encrypted, rotating ChatGPT session checkpoint for manual GitHub Actions runs.

The Actions artifact contains only AES-GCM ciphertext. The encryption key stays
in a repository Secret; never print either the key or decrypted session.
"""

import argparse
import base64
import io
import json
import os
import subprocess
import zipfile
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from chatgpt_auth import ChatGPTSession, _read_private, _write_private

REPOSITORY = "ohjun1998/passive-scan_v8.0.1_pub"
ARTIFACT_NAME = "chatgpt-ci-session"
CHECKPOINT = "session.enc"
AAD = (REPOSITORY + "/" + ARTIFACT_NAME + "/v1").encode()


def _key():
    encoded = os.environ.get("CHATGPT_CI_KEY", "")
    key = base64.b64decode(encoded, validate=True)
    if len(key) != 32:
        raise RuntimeError("CHATGPT_CI_KEY must contain a 256-bit key")
    return key


def seal(record, key):
    nonce = os.urandom(12)
    plaintext = json.dumps(record, separators=(",", ":")).encode()
    return b"PSCI1" + nonce + AESGCM(key).encrypt(nonce, plaintext, AAD)


def unseal(blob, key):
    if not blob.startswith(b"PSCI1") or len(blob) > 32_768:
        raise RuntimeError("Invalid encrypted session checkpoint")
    return json.loads(AESGCM(key).decrypt(blob[5:17], blob[17:], AAD))


def _validate(record):
    if not isinstance(record, dict) or not all(
        isinstance(record.get(field), str) and record[field] for field in
        ("client_id", "subject", "access_token", "refresh_token", "scope")
    ) or "chatgpt.tokens.use.direct" not in record["scope"].split():
        raise RuntimeError("ChatGPT session checkpoint is incomplete")
    if not isinstance(record.get("expires_at"), (int, float)):
        raise RuntimeError("ChatGPT session expiry is missing")
    return record


def _gh_api(path):
    return subprocess.run(["gh", "api", "-H", "Accept: application/vnd.github+json",
                           path], check=True, stdout=subprocess.PIPE).stdout


def latest_checkpoint():
    raw = _gh_api(f"repos/{REPOSITORY}/actions/artifacts?name={ARTIFACT_NAME}&per_page=100")
    artifacts = json.loads(raw).get("artifacts", [])
    candidates = [item for item in artifacts if not item.get("expired") and
                  item.get("name") == ARTIFACT_NAME and
                  item.get("workflow_run", {}).get("head_branch") == "main"]
    if not candidates:
        return None
    latest = max(candidates, key=lambda item: (item["created_at"], item["id"]))
    archive = _gh_api(f"repos/{REPOSITORY}/actions/artifacts/{latest['id']}/zip")
    if len(archive) > 100_000:
        raise RuntimeError("Encrypted session artifact is unexpectedly large")
    with zipfile.ZipFile(io.BytesIO(archive)) as zf:
        if zf.namelist() != [CHECKPOINT] or zf.getinfo(CHECKPOINT).file_size > 32_768:
            raise RuntimeError("Unexpected session artifact contents")
        return zf.read(CHECKPOINT)


def restore(directory):
    key = _key()
    checkpoint = None if os.environ.get("CHATGPT_CI_RESET") == "true" else latest_checkpoint()
    if checkpoint is None:
        source = os.environ.get("CHATGPT_CI_BOOTSTRAP", "")
        if not source:
            raise RuntimeError("No session artifact or initial ChatGPT bootstrap secret")
        record = json.loads(source)
    else:
        record = unseal(checkpoint, key)
    session = ChatGPTSession(directory)
    _write_private(session.session_file, _validate(record))
    print("Protected ChatGPT session restored for this run")


def checkpoint(directory, output):
    record = _read_private(ChatGPTSession(directory).session_file)
    if record is None:
        raise RuntimeError("No ChatGPT session to checkpoint")
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    output.write_bytes(seal(_validate(record), _key()))
    os.chmod(output, 0o600)
    print("Encrypted ChatGPT session checkpoint ready")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["restore", "checkpoint"])
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.command == "restore":
        restore(args.directory)
    else:
        if not args.output:
            parser.error("--output is required for checkpoint")
        checkpoint(args.directory, args.output)
