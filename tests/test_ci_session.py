import base64
import io
import json
import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

import ci_session
from chatgpt_auth import ChatGPTSession, _read_private, _write_private


def fake_record(refresh="first"):
    return {"client_id": "oaiapp_test", "subject": "test-account",
            "access_token": "private-access", "refresh_token": refresh,
            "scope": "openid chatgpt.tokens.use.direct", "expires_at": 42}


class CheckpointTests(unittest.TestCase):
    def test_encryption_rejects_wrong_key_and_tampering(self):
        key = os.urandom(32)
        ciphertext = ci_session.seal(fake_record(), key)
        self.assertNotIn(b"private-access", ciphertext)
        self.assertEqual(ci_session.unseal(ciphertext, key)["refresh_token"], "first")
        with self.assertRaises(Exception):
            ci_session.unseal(ciphertext, os.urandom(32))
        with self.assertRaises(Exception):
            ci_session.unseal(ciphertext[:-1] + bytes([ciphertext[-1] ^ 1]), key)

    def test_bootstrap_then_restore_rotated_artifact(self):
        key = os.urandom(32)
        environment = {"CHATGPT_CI_KEY": base64.b64encode(key).decode(),
                       "CHATGPT_CI_BOOTSTRAP": json.dumps(fake_record())}
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, environment):
            directory = Path(tmp) / "session"
            with patch("ci_session.latest_checkpoint", return_value=None):
                ci_session.restore(directory)
            record = _read_private(ChatGPTSession(directory).session_file)
            self.assertEqual(record["refresh_token"], "first")
            record["refresh_token"] = "rotated"
            _write_private(ChatGPTSession(directory).session_file, record)
            sealed = Path(tmp) / "artifact" / ci_session.CHECKPOINT
            ci_session.checkpoint(directory, sealed)
            with patch("ci_session.latest_checkpoint", return_value=sealed.read_bytes()):
                ci_session.restore(Path(tmp) / "next-run")
            self.assertEqual(_read_private(ChatGPTSession(Path(tmp) / "next-run").session_file)
                             ["refresh_token"], "rotated")

    def test_latest_checkpoint_accepts_only_main_and_expected_file(self):
        blob = ci_session.seal(fake_record(), os.urandom(32))
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w") as zipped:
            zipped.writestr(ci_session.CHECKPOINT, blob)
        data = {"artifacts": [
            {"id": 10, "name": ci_session.ARTIFACT_NAME, "created_at": "2026-10-01",
             "expired": False, "workflow_run": {"head_branch": "feature"}},
            {"id": 11, "name": ci_session.ARTIFACT_NAME, "created_at": "2026-10-02",
             "expired": False, "workflow_run": {"head_branch": "main"}},
        ]}
        with patch("ci_session._gh_api", side_effect=[json.dumps(data).encode(), archive.getvalue()]):
            self.assertEqual(ci_session.latest_checkpoint(), blob)


if __name__ == "__main__":
    unittest.main()
