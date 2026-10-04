import base64
import json
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import ai_review
import chatgpt_auth


class ChatGPTTests(unittest.TestCase):
    def test_refresh_rotates_credentials_and_reuses_host_id(self):
        with tempfile.TemporaryDirectory() as directory:
            session = chatgpt_auth.ChatGPTSession(directory)
            self.assertEqual(session._host_id(), session._host_id())
            self.assertTrue(session._host_id().startswith("urn:uuid:"))
            chatgpt_auth._write_private(session.session_file, {
                "client_id": "oaiapp_example", "subject": "owned-test-account",
                "scope": "chatgpt.tokens.use.direct", "refresh_token": "old",
                "access_token": "expired", "expires_at": 0,
            })
            response = {"access_token": "new", "refresh_token": "replacement",
                        "expires_in": 3600, "scope": "chatgpt.tokens.use.direct"}
            with patch("chatgpt_auth._request_json", return_value=response) as request:
                self.assertEqual(session.access_token(), "new")
                self.assertEqual(session.access_token(), "new")
            self.assertEqual(request.call_count, 1)
            self.assertEqual(request.call_args.args[1]["refresh_token"], "old")
            self.assertEqual(chatgpt_auth._read_private(session.session_file)["refresh_token"], "replacement")
            self.assertEqual(session.session_file.stat().st_mode & 0o777, 0o600)

    def test_stream_requires_completion_and_rejects_unapproved_action(self):
        planner = ai_review.ChatGPTPlanner.__new__(ai_review.ChatGPTPlanner)
        planner.model = "available-model"
        planner.session = SimpleNamespace(access_token=lambda: "fake-test-token")

        class Stream:
            def __init__(self, events):
                self.events = events

            def __enter__(self):
                return iter(self.events)

            def __exit__(self, *_args):
                pass

        create = Mock(return_value=Stream([
            SimpleNamespace(type="response.output_text.delta", delta='{"action":"delete","reason":"no"}'),
            SimpleNamespace(type="response.completed"),
        ]))
        planner.OpenAI = lambda **kwargs: SimpleNamespace(responses=SimpleNamespace(create=create))
        result = planner.choose("https://example.test/api/orders/123", ["anonymous"], [])
        self.assertEqual(result["action"], "stop")
        arguments = create.call_args.kwargs
        self.assertEqual(arguments["input"][0]["role"], "user")
        self.assertTrue(arguments["stream"])
        self.assertFalse(arguments["store"])
        create.return_value = Stream([SimpleNamespace(type="response.output_text.delta",
                                                     delta='{"action":"anonymous"}')])
        with self.assertRaises(RuntimeError):
            planner.choose("https://example.test/api/orders/123", ["anonymous"], [])

    def test_id_token_signature_and_claims(self):
        from cryptography.hazmat.primitives.asymmetric import rsa, padding
        from cryptography.hazmat.primitives import hashes

        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        numbers = private.public_key().public_numbers()
        encode_int = lambda value: chatgpt_auth._b64(value.to_bytes((value.bit_length() + 7) // 8, "big"))
        jwk = {"kid": "test", "kty": "RSA", "n": encode_int(numbers.n), "e": encode_int(numbers.e)}
        header = chatgpt_auth._b64(json.dumps({"alg": "RS256", "kid": "test"}).encode())
        payload = chatgpt_auth._b64(json.dumps({"iss": chatgpt_auth.AUTH, "aud": "issued-id",
                                             "nonce": "random-nonce", "sub": "subject",
                                             "exp": time.time() + 300}).encode())
        signing_input = f"{header}.{payload}".encode()
        signature = private.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        token = f"{header}.{payload}.{chatgpt_auth._b64(signature)}"
        def discovery(url, *args, **kwargs):
            return {"jwks_uri": chatgpt_auth.AUTH + "/keys"} if url.endswith("openid-configuration") else {"keys": [jwk]}
        with patch("chatgpt_auth._request_json", side_effect=discovery):
            self.assertEqual(chatgpt_auth._verify_id_token(token, "issued-id", "random-nonce")["sub"], "subject")
            with self.assertRaises(RuntimeError):
                chatgpt_auth._verify_id_token(token, "different-id", "random-nonce")


if __name__ == "__main__":
    unittest.main()
