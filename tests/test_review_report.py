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
        self.assertIn("반사 확인: 200", text)
        self.assertIn("수동 확인: 입력값 반사", text)
        for secret in ("lab.test", "private-token", "private-response-data", "private-reason-data"):
            self.assertNotIn(secret, text)

    def test_html_never_executes_reflected_response(self):
        row = {"url": "https://lab.test/search?q=<script>alert(1)</script>",
               "state": "completed", "categories": ["input_reflection"],
               "observations": [{"action": "reflection", "status": 200,
                                 "preview": "<img src=x onerror=alert(1)>", "marker_reflected": True}],
               "findings": [{"kind": "reflected_input", "status": "manual_review",
                             "reason": "<script>alert(1)</script>"}]}
        report = review_report.detail_html(row, 1, 1)
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
        report = review_report.detail_html(row, 1, 1)
        self.assertIn("Can B read A&#x27;s test object?", report)
        self.assertIn('href="#obs-1"', report)
        self.assertIn('id="obs-1"', report)
        self.assertIn("응답 SHA-256: <code>abc</code>", report)

    def test_dashboard_links_to_each_detail_and_back_without_exposing_other_previews(self):
        rows = [{"url": f"https://lab.test/page/{i}", "state": "completed",
                 "categories": ["basic_response"], "observations": [
                     {"action": "anonymous", "status": 200, "preview": f"secret-{i}"}],
                 "findings": []} for i in range(1, 3)]
        dashboard = review_report.readable_html(rows)
        self.assertIn('href="pages/candidate-001.html"', dashboard)
        self.assertIn('href="pages/candidate-002.html"', dashboard)
        self.assertIn("메인 대시보드", dashboard)
        self.assertNotIn("secret-1", dashboard)
        detail = review_report.detail_html(rows[0], 1, 2)
        self.assertIn("secret-1", detail)
        self.assertNotIn("secret-2", detail)
        self.assertIn('href="../review_report.html"', detail)
        self.assertIn('href="candidate-002.html"', detail)

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
                self.assertEqual(stream.namelist(), ["review_report.html", "pages/candidate-001.html",
                                                     "ai_review_results.jsonl"])
                with self.assertRaises(RuntimeError):
                    stream.read("ai_review_results.jsonl", pwd=b"wrong-password")
                self.assertEqual(stream.read("ai_review_results.jsonl", pwd=b"test-password"),
                                 source.read_bytes())
                self.assertIn(b'pages/candidate-001.html',
                              stream.read("review_report.html", pwd=b"test-password"))


if __name__ == "__main__":
    unittest.main()
