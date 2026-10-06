#!/usr/bin/env python3
"""Render bounded review results for GitHub and a protected, readable archive."""

import argparse
import collections
import html
import json
import os
from pathlib import Path


def load_rows(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def summary(rows):
    states = collections.Counter(row["state"] if row["state"] in {
        "completed", "dry_run", "model_unavailable", "request_error", "halted_on_server_signal"
    } else "other" for row in rows)
    statuses = collections.Counter(str(obs["status"]) for row in rows for obs in row["observations"]
                                   if isinstance(obs.get("status"), int) and 100 <= obs["status"] <= 599)
    findings = collections.Counter(f["kind"] for row in rows for f in row["findings"]
                                   if f.get("kind") in {"reflected_input", "access_control"})
    lines = ["## Bounded review summary", "", "| Metric | Count |", "| --- | ---: |",
             f"| Candidates | {len(rows)} |"]
    for label, values in (("State", states), ("HTTP", statuses), ("Manual review", findings)):
        lines.extend(f"| {label}: {key} | {count} |" for key, count in sorted(values.items()))
    lines += ["", "### Candidates (URLs and response bodies omitted)", "",
              "| # | State | Categories | Actions / HTTP | Findings |",
              "| ---: | --- | --- | --- | --- |"]
    for number, row in enumerate(rows, 1):
        # Whitelist expected fields: candidate URLs, query values and response previews
        # must never enter the GitHub job summary or public workflow logs.
        state = row["state"] if row["state"] in {
            "completed", "dry_run", "model_unavailable", "request_error", "halted_on_server_signal"
        } else "other"
        categories = ", ".join(c for c in row["categories"] if c in {
            "object_access", "role_access", "input_reflection", "basic_response"
        }) or "—"
        actions = ", ".join(f"{obs['action']}: {obs['status']}" for obs in row["observations"]
                            if obs.get("action") in {"anonymous", "a", "b", "reflection"}
                            and isinstance(obs.get("status"), int)) or "—"
        kinds = ", ".join(f"{f['kind']} ({f['status']})" for f in row["findings"]
                          if f.get("kind") in {"reflected_input", "access_control"}
                          and f.get("status") == "manual_review") or "—"
        lines.append(f"| {number} | {state} | {categories} | {actions} | {kinds} |")
    lines += ["", "Findings require manual confirmation. Download the protected readable report for URLs and evidence.", ""]
    return "\n".join(lines)


def readable_html(rows):
    escape = lambda value: html.escape(str(value), quote=True)
    cards = []
    for number, row in enumerate(rows, 1):
        hypotheses = "".join("<li><strong>{}</strong> — {}<br>{}<br><small>{}</small></li>".format(
            escape(item.get("kind", "")), escape(item.get("status", "")),
            escape(item.get("question", "")), escape(item.get("limit", "")))
            for item in row.get("hypotheses", [])) or "<li>None recorded</li>"
        plans = "".join("<li>{}: {} <small>(model inference)</small></li>".format(
            escape(item.get("action", "")), escape(item.get("question", "")))
            for item in row.get("plans", [])) or "<li>None recorded</li>"
        facts = "".join("<li><strong>{}</strong> — {} / HTTP {}, SHA-256 <code>{}</code></li>".format(
            escape(item.get("evidence_id", "")), escape(item.get("action", "")),
            escape(item.get("http_status", "")), escape(item.get("body_sha256", "")))
            for item in row.get("facts", [])) or "<li>None recorded</li>"
        observations = "".join(
            "<tr><td>obs-{}</td><td>{}</td><td>{}</td><td>{}</td><td><pre>{}</pre></td></tr>".format(
                index,
                escape(obs.get("action", "")), escape(obs.get("status", "")),
                escape("yes" if obs.get("marker_reflected") else "no"),
                escape(obs.get("preview", ""))) for index, obs in enumerate(row.get("observations", []), 1))
        findings = "".join("<li><strong>{}</strong> ({}) — {}. Evidence: {}</li>".format(
            escape(item.get("kind", "")), escape(item.get("status", "")),
            escape(item.get("reason", "")),
            escape(", ".join(item.get("evidence_ids", [])) or "not linked"))
            for item in row.get("findings", [])) or "<li>None</li>"
        cards.append("<section><h2>Candidate {}</h2><p><strong>URL:</strong> <code>{}</code></p>"
                     "<p><strong>State:</strong> {} · <strong>Categories:</strong> {}</p>"
                     "<h3>Hypotheses</h3><ul>{}</ul><h3>Model plans</h3><ul>{}</ul>"
                     "<h3>Observed facts</h3><ul>{}</ul><h3>Manual review candidates</h3><ul>{}</ul>"
                     "<h3>Observations</h3><table><thead><tr><th>Evidence ID</th><th>Action</th>"
                     "<th>HTTP</th><th>Marker reflected</th><th>Response preview</th>"
                     "</tr></thead><tbody>{}</tbody></table></section>".format(
                         number, escape(row.get("url", "")), escape(row.get("state", "")),
                         escape(", ".join(row.get("categories", []))), hypotheses, plans,
                         facts, findings, observations))
    return ("<!doctype html><html lang=\"ko\"><head><meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
            "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">"
            "<title>Bounded review report</title><style>body{font:16px/1.5 system-ui;margin:"
            "auto;max-width:960px;padding:20px;color:#17212b}section{border:1px solid #ddd;"
            "border-radius:8px;padding:16px;margin:20px 0}table{border-collapse:collapse;width:100%}"
            "td,th{border:1px solid #ddd;padding:8px;text-align:left;vertical-align:top}"
            "pre{white-space:pre-wrap;overflow-wrap:anywhere;max-width:560px}code{overflow-wrap:anywhere}"
            "</style></head><body><h1>Bounded review report</h1><p>Candidate observations "
            "require manual confirmation. A reflected marker alone does not establish XSS.</p>"
            + "".join(cards) + "</body></html>")


def archive(rows, input_path, output_path, password):
    if not password:
        raise ValueError("ACTIONS_CRYPTO_PASSWORD is required")
    import pyzipper
    with pyzipper.AESZipFile(output_path, "w", compression=pyzipper.ZIP_DEFLATED) as stream:
        stream.setpassword(password.encode("utf-8"))
        stream.setencryption(pyzipper.WZ_AES, nbits=256)
        stream.writestr("review_report.html", readable_html(rows).encode("utf-8"))
        stream.write(input_path, "ai_review_results.jsonl")
    with pyzipper.AESZipFile(output_path) as stream:
        stream.setpassword(password.encode("utf-8"))
        if stream.read("ai_review_results.jsonl") != input_path.read_bytes():
            raise RuntimeError("Readable archive verification failed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    args = parser.parse_args()
    rows = load_rows(args.input)
    password = os.environ.get("REPORT_PASSWORD", "")
    if not password:
        parser.error("ACTIONS_CRYPTO_PASSWORD is required")
    archive(rows, args.input, args.archive, password)
    with args.summary.open("a", encoding="utf-8") as stream:
        stream.write(summary(rows))


if __name__ == "__main__":
    main()
