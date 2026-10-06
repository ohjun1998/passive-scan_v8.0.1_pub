import tempfile
import unittest
import json
from pathlib import Path

import review_report


class ReviewReportTests(unittest.TestCase):
    def test_summary_has_candidate_details_without_sensitive_values(self):
        row = {"url": "https://lab.test/search?q=private-token",
               "state": "completed", "categories": ["input_reflection"],
               "observations": [{"action": "reflection", "status": 200,
                                 "preview": "private-response-data", "marker_reflected": True}],
               "findings": [{"kind": "reflected_input", "status": "manual_review",
                             "reason": "private-reason-data"}]}
        text = review_report.summary([row])
        self.assertIn("reflection: 200", text)
        self.assertIn("reflected_input (manual_review)", text)
        for secret in ("lab.test", "private-token", "private-response-data", "private-reason-data"):
            self.assertNotIn(secret, text)

    def test_html_never_executes_reflected_response(self):
        row = {"url": "https://lab.test/search?q=<script>alert(1)</script>",
               "state": "completed", "categories": ["input_reflection"],
               "observations": [{"action": "reflection", "status": 200,
                                 "preview": "<img src=x onerror=alert(1)>", "marker_reflected": True}],
               "findings": [{"kind": "reflected_input", "status": "manual_review",
                             "reason": "<script>alert(1)</script>"}]}
        report = review_report.readable_html([row])
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;", report)
        self.assertIn("q=&lt;script&gt;alert(1)&lt;/script&gt;", report)
        self.assertNotIn("<script>", report)
        self.assertIn("default-src 'none'", report)

    def test_html_links_hypothesis_to_observed_evidence(self):
        row = {"url": "https://lab.test/api/orders/123", "state": "completed",
               "categories": ["object_access"],
               "hypotheses": [{"kind": "access_control", "status": "needs_manual_review",
                               "question": "Can B read A's test object?", "limit": "Check sharing policy."}],
               "plans": [{"action": "a", "question": "Read owner baseline?", "confidence": "inferred"}],
               "facts": [{"evidence_id": "obs-1", "action": "a", "http_status": 200,
                          "body_sha256": "abc", "confidence": "observed"}],
               "observations": [{"action": "a", "status": 200, "preview": "test",
                                 "marker_reflected": False}],
               "findings": [{"kind": "access_control", "status": "manual_review",
                             "reason": "Other identity saw marker", "evidence_ids": ["obs-1"]}]}
        report = review_report.readable_html([row])
        self.assertIn("Can B read A&#x27;s test object?", report)
        self.assertIn("Evidence: obs-1", report)
        self.assertIn("SHA-256 <code>abc</code>", report)

    def test_encrypted_zip_round_trip_and_wrong_password(self):
        try:
            import pyzipper
        except ImportError:
            self.skipTest("pyzipper is installed by GitHub CI")
        row = {"url": "https://lab.test/search?q=private", "state": "completed",
               "categories": ["input_reflection"], "observations": [], "findings": []}
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "results.jsonl"
            target = Path(directory) / "protected.zip"
            source.write_text(json.dumps(row) + "\n")
            review_report.archive([row], source, target, "test-password")
            with pyzipper.AESZipFile(target) as stream:
                self.assertEqual(stream.namelist(), ["review_report.html", "ai_review_results.jsonl"])
                with self.assertRaises(RuntimeError):
                    stream.read("ai_review_results.jsonl", pwd=b"wrong-password")
                self.assertEqual(stream.read("ai_review_results.jsonl", pwd=b"test-password"),
                                 source.read_bytes())


if __name__ == "__main__":
    unittest.main()
