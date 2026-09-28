import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import global_mixer
import js_assets
import txt_to_excel
from openpyxl import load_workbook


class ReconRegressionTests(unittest.TestCase):
    def test_katana_and_more_than_five_urls_survive(self):
        original = Path.cwd()
        with tempfile.TemporaryDirectory() as tmp:
            os.chdir(tmp)
            try:
                Path("targets.txt").write_text("example.test\n")
                Path("results").mkdir()
                urls = [f"https://example.test/api/users/{n}" for n in range(8)]
                Path("results/example.test_katana_00.txt").write_text("\n".join(urls) + "\n")
                global_mixer.run_mixer()
                actual = set()
                for path in Path("chunks").glob("chunk_*.txt"):
                    actual.update(path.read_text().splitlines())
                self.assertEqual(actual, set(urls))
            finally:
                os.chdir(original)

    def test_historical_urls_respect_current_scope(self):
        original = Path.cwd()
        with tempfile.TemporaryDirectory() as tmp:
            os.chdir(tmp)
            try:
                Path("targets.txt").write_text("example.test\n")
                Path("previous_report").mkdir()
                with sqlite3.connect("previous_report/recon_history.db") as db:
                    db.execute("CREATE TABLE master_urls(url TEXT)")
                    db.executemany("INSERT INTO master_urls VALUES(?)",
                                   [("https://example.test/old",), ("https://outside.test/private",)])
                global_mixer.run_mixer()
                actual = "\n".join(path.read_text() for path in Path("chunks").glob("chunk_*.txt"))
                self.assertIn("https://example.test/old", actual)
                self.assertNotIn("outside.test", actual)
            finally:
                os.chdir(original)

    def test_js_names_include_url_and_content_hash(self):
        body = b"console.log('v1')"
        opener = Mock()
        response = Mock()
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=None)
        response.headers = {"Content-Type": "application/javascript"}
        response.read.return_value = body
        opener.open.return_value = response
        with tempfile.TemporaryDirectory() as tmp:
            a = js_assets.download("https://example.test/a/app.js?v=1", {"example.test"}, Path(tmp), opener)
            b = js_assets.download("https://example.test/b/app.js?v=1", {"example.test"}, Path(tmp), opener)
            self.assertNotEqual(a[0], b[0])
            self.assertEqual(Path(tmp, a[0]).read_bytes(), body)
            self.assertIsNone(js_assets.download("https://outside.test/app.js", {"example.test"}, Path(tmp), opener))

    def test_report_separates_unprobed_and_secret_findings(self):
        original = Path.cwd()
        with tempfile.TemporaryDirectory() as tmp:
            os.chdir(tmp)
            try:
                Path("targets.txt").write_text("example.test\n")
                Path("results").mkdir()
                Path("results/example.test_gau_00.txt").write_text("https://example.test/api/users/123\n")
                Path("results/example.test_trufflehog_00.txt").write_text("app.js\tGeneric\tverified\n")
                with patch.object(txt_to_excel, "run_duckduckgo_dorking", return_value=[]), patch.object(
                    txt_to_excel, "analyze_all_subdomains", return_value={}):
                    txt_to_excel.build_advanced_excel_report()
                report = next(Path("reports").glob("*.xlsx"))
                workbook = load_workbook(report, read_only=True)
                self.assertEqual(workbook["🔐 Secrets (검토)"]["C2"].value, "Generic")
                self.assertEqual(workbook["example.test"]["C3"].value, "NotProbed")
                with sqlite3.connect("reports/recon_history.db") as db:
                    self.assertEqual(db.execute("SELECT COUNT(*) FROM master_urls").fetchone()[0], 1)
            finally:
                os.chdir(original)


if __name__ == "__main__":
    unittest.main()
