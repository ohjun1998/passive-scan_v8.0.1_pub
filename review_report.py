#!/usr/bin/env python3
"""Generate one Korean dashboard with embedded detail views inside an AES ZIP."""

import argparse
import collections
import html
import json
import os
from pathlib import Path

STATES = {"completed": "검토 완료", "dry_run": "요청 없는 미리보기",
          "model_unavailable": "모델 사용 불가", "request_error": "요청 오류",
          "halted_on_server_signal": "서버 신호로 중단"}
CATEGORIES = {"object_access": "객체 접근", "role_access": "역할별 접근",
              "input_reflection": "입력값 반사", "basic_response": "기본 응답"}
FINDINGS = {"reflected_input": "입력값 반사", "access_control": "접근 통제"}
HYPOTHESES = {"not_tested": "미검증", "needs_manual_review": "수동 확인 필요",
              "no_signal_observed": "신호 관찰되지 않음"}
ACTIONS = {"anonymous": "비로그인", "a": "계정 A", "b": "계정 B",
           "reflection": "반사 확인", "sql_error": "SQL 오류 신호 확인",
           "upload": "무해한 텍스트 업로드", "stop": "중단"}
TESTS = {"access_control": "인가", "reflection": "입력 반사",
         "sql_error": "SQL 오류 신호", "upload": "파일 업로드"}
HYPOTHESIS_TEXT = {
    "reflected_input": ("무해한 검색 표식이 응답에 나타나는가?",
                        "반사만으로 스크립트 실행 여부를 판단할 수 없습니다."),
    "access_control": ("다른 계정에서 소유자의 테스트 객체 표식을 읽을 수 있는가?",
                       "테스트 객체의 공유 정책은 사람이 확인해야 합니다."),
}
FINDING_TEXT = {
    "reflected_input": "무해한 표식의 반사가 관찰됐습니다. 스크립트 실행 여부는 확인하지 않았습니다.",
    "access_control": "다른 신원에도 소유자의 테스트 표식이 반환됐습니다. 의도한 공유 정책을 확인하세요.",
}
PLAN_TEXT = {"anonymous": "비로그인 상태의 응답 확인", "a": "계정 A의 응답 확인",
             "b": "계정 B의 응답 확인", "reflection": "검색 표식의 반사 확인",
             "stop": "추가 요청 중단"}


def load_rows(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def escape(value):
    return html.escape(str(value), quote=True)


def labels(values, mapping):
    return ", ".join(mapping.get(value, "기타") for value in values) or "없음"


def page_id(number):
    return f"candidate-{number:03d}"


def counts(rows):
    states = collections.Counter(row.get("state") if row.get("state") in STATES else "other" for row in rows)
    statuses = collections.Counter(str(obs["status"]) for row in rows for obs in row.get("observations", [])
                                   if isinstance(obs.get("status"), int) and 100 <= obs["status"] <= 599)
    findings = collections.Counter(f["kind"] for row in rows for f in row.get("findings", [])
                                   if f.get("kind") in FINDINGS and f.get("status") == "manual_review")
    return states, statuses, findings


def summary(rows):
    states, statuses, findings = counts(rows)
    lines = ["## 한정 범위 검토 요약", "", "| 항목 | 건수 |", "| --- | ---: |",
             f"| 검토 페이지 | {len(rows)} |"]
    for title, values, mapping in (("상태", states, STATES), ("HTTP", statuses, {}),
                                   ("수동 확인", findings, FINDINGS)):
        lines.extend(f"| {title}: {mapping.get(key, key)} | {value} |"
                     for key, value in sorted(values.items()))
    lines += ["", "### 페이지별 결과 (URL과 응답 내용 제외)", "",
              "| 번호 | 상태 | 분류 | 테스트 후보 | 요청 / HTTP | 수동 확인 |",
              "| ---: | --- | --- | --- | --- | --- |"]
    for number, row in enumerate(rows, 1):
        state = STATES.get(row.get("state"), "기타")
        categories = labels((c for c in row.get("categories", []) if c in CATEGORIES), CATEGORIES)
        actions = ", ".join(f"{ACTIONS[obs['action']]}: {obs['status']}"
                            for obs in row.get("observations", [])
                            if obs.get("action") in ACTIONS and isinstance(obs.get("status"), int)) or "—"
        kinds = ", ".join(FINDINGS[f["kind"]] for f in row.get("findings", [])
                          if f.get("kind") in FINDINGS and f.get("status") == "manual_review") or "—"
        tests = ", ".join(TESTS[c["kind"]] for c in row.get("test_candidates", [])
                          if c.get("kind") in TESTS) or "—"
        lines.append(f"| {number} | {state} | {categories} | {tests} | {actions} | {kinds} |")
    lines += ["", "수동 확인 대상은 취약점 확정이 아닙니다. URL과 근거는 보호된 HTML 보고서에서 확인하세요.", ""]
    return "\n".join(lines)


CSS = """
:root{color-scheme:light;--bg:#f4f7fb;--ink:#172436;--muted:#53667a;--line:#dce5ee;--accent:#1557a5;--pale:#eaf2fc;--warn:#9a570a;--warn-bg:#fff3df;--ok:#176247}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.6 system-ui,-apple-system,sans-serif}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}a:focus-visible{outline:3px solid var(--accent);outline-offset:3px}
.shell{max-width:1160px;margin:auto;padding:28px 20px 64px}.top{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}
.brand{font-weight:800;color:var(--ink)}.eyebrow{color:var(--accent);font-size:.8rem;font-weight:800;letter-spacing:.08em}
h1{font-size:clamp(1.8rem,4vw,2.6rem);line-height:1.2;margin:.4rem 0 1rem}h2{font-size:1.3rem;margin:0 0 1rem}
.muted,.intro{color:var(--muted)}.intro{max-width:760px}
.notice{background:var(--warn-bg);border-left:4px solid #db9c31;padding:14px 18px;border-radius:8px;margin:22px 0}
.stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;margin:24px 0}
.stat,.panel{background:#fff;border:1px solid var(--line);border-radius:14px;box-shadow:0 3px 16px #1e3d6109}
.stat{padding:18px}.stat span{color:var(--muted);font-size:.9rem}.stat strong{display:block;font-size:2rem;line-height:1.2;margin-top:6px}
.panel{padding:22px;margin:18px 0}.table-wrap{overflow-x:auto}.table{border-collapse:collapse;width:100%;min-width:650px}
.table th,.table td{text-align:left;padding:14px 12px;border-bottom:1px solid var(--line);vertical-align:top}
.table th{color:var(--muted);font-size:.85rem;font-weight:700}.table tr:last-child td{border-bottom:0}
.url,pre,code{overflow-wrap:anywhere;word-break:break-word}.url{font-size:.88rem;color:var(--muted);margin:.25rem 0 0}
.badge{display:inline-block;padding:3px 9px;border-radius:999px;background:var(--pale);color:var(--accent);font-size:.82rem;font-weight:700}
.badge.warn{background:var(--warn-bg);color:var(--warn)}.badge.ok{background:#e5f5ed;color:var(--ok)}
.link{font-weight:700}.detail-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:18px}
.detail-grid .panel{margin:0}.list{padding-left:1.25rem;margin:0}.list li{margin:.7rem 0}.list li:first-child{margin-top:0}
.sub{font-size:.88rem;color:var(--muted)}.evidence{display:inline-block;font:700 .82rem ui-monospace,monospace;background:var(--pale);padding:3px 7px;border-radius:5px}
.preview{white-space:pre-wrap;background:#f5f7fa;padding:12px;border-radius:8px;max-width:480px;margin:0;font-size:.85rem}
.nav{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;margin:28px 0}.empty{color:var(--muted);margin:0}
.detail-page{display:none}.detail-page:target,.detail-page:has(:target){display:block}
body:has(.detail-page:target,.detail-page :target) #dashboard{display:none}
@media(max-width:750px){.stats{grid-template-columns:repeat(2,minmax(0,1fr))}.detail-grid{grid-template-columns:1fr}.shell{padding:20px 14px 48px}}
"""


def document(title, body):
    return ('<!doctype html><html lang="ko"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width, initial-scale=1">'
            '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'">'
            f'<title>{escape(title)}</title><style>{CSS}</style></head><body>{body}</body></html>')


def readable_html(rows):
    """Dashboard entry point; URLs and previews remain inside the encrypted archive."""
    states, statuses, findings = counts(rows)
    stats = (("검토 페이지", len(rows)), ("완료", states["completed"]),
             ("HTTP 응답", sum(statuses.values())), ("수동 확인 항목", sum(findings.values())))
    tiles = "".join(f'<div class="stat"><span>{label}</span><strong>{value}</strong></div>'
                    for label, value in stats)
    entries = []
    for number, row in enumerate(rows, 1):
        flagged = sum(f.get("status") == "manual_review" for f in row.get("findings", []))
        badge = (f'<span class="badge warn">수동 확인 {flagged}건</span>' if flagged
                 else '<span class="badge ok">표시 항목 없음</span>')
        entries.append(f'<tr><td>{number}</td><td><a class="link" href="#{page_id(number)}">페이지 {number:02d} 상세 보기</a>'
                       f'<p class="url">{escape(row.get("url", ""))}</p></td>'
                       f'<td>{escape(labels(row.get("categories", []), CATEGORIES))}</td>'
                       f'<td>{escape(labels((c.get("kind") for c in row.get("test_candidates", [])), TESTS))}</td>'
                       f'<td>{escape(STATES.get(row.get("state"), "기타"))}</td>'
                       f'<td>{len(row.get("observations", []))}</td><td>{badge}</td></tr>')
    table = ('<div class="table-wrap"><table class="table"><thead><tr><th>번호</th><th>대상 페이지</th>'
             '<th>검토 분류</th><th>테스트 후보</th><th>진행 상태</th><th>HTTP 관찰</th><th>결과</th></tr></thead><tbody>'
             + "".join(entries) + '</tbody></table></div>') if entries else '<p class="empty">검토 결과가 없습니다.</p>'
    body = ('<main id="dashboard" class="shell"><header class="top"><span class="brand">PASSIVE SCAN · 검토 보고서</span>'
            '<span class="badge">보호된 보고서</span></header><p class="eyebrow">검토 현황</p>'
            '<h1>메인 대시보드</h1><p class="intro">정찰 결과에서 선정한 페이지의 제한된 HTTP 관찰과 수동 확인 대상을 확인합니다. '
            '페이지를 선택하면 가설, 모델 계획, 관찰 근거와 응답 미리보기를 볼 수 있습니다.</p>'
            '<div class="notice">수동 확인 항목은 취약점 확정이 아닙니다. 특히 입력값 반사만으로 XSS 실행을 입증할 수 없습니다.</div>'
            f'<div class="stats">{tiles}</div><section class="panel"><h2>페이지별 결과</h2>{table}</section>'
            '<p class="muted">원본 데이터는 압축파일의 ai_review_results.jsonl에 함께 들어 있습니다.</p></main>')
    body += "".join(detail_section(row, number, len(rows))
                    for number, row in enumerate(rows, 1))
    return document("검토 대시보드 | Passive Scan", body)


def detail_section(row, number, total):
    def listing(items):
        return '<ul class="list">' + "".join(f'<li>{item}</li>' for item in items) + '</ul>' if items else '<p class="empty">기록 없음</p>'

    hypotheses = [f'<strong>{escape(FINDINGS.get(x.get("kind"), "기타"))}</strong> '
                  f'<span class="badge">{escape(HYPOTHESES.get(x.get("status"), "상태 미상"))}</span>'
                  f'<div>{escape(HYPOTHESIS_TEXT.get(x.get("kind"), ("검토 가설의 원문을 확인하세요.", ""))[0])}</div>'
                  f'<div class="sub">{escape(HYPOTHESIS_TEXT.get(x.get("kind"), ("", ""))[1])}</div>'
                  f'<details class="sub"><summary>가설 원문</summary>{escape(x.get("question", ""))}<br>{escape(x.get("limit", ""))}</details>'
                  for x in row.get("hypotheses", [])]
    candidates = [f'<strong>{escape(TESTS.get(x.get("kind"), "기타"))}</strong> '
                  f'<span class="badge">{("테스트 정의 준비" if x.get("status") == "ready" else "추가 설정 필요")}</span>'
                  f'<div>{escape(x.get("signal", ""))}</div>'
                  f'<div class="sub">필요 조건: {escape(x.get("prerequisite", ""))}</div>'
                  for x in row.get("test_candidates", [])]
    plans = [f'<strong>{escape(PLAN_TEXT.get(x.get("action"), "기타 계획"))}</strong> · 모델 추론'
             f'<details class="sub"><summary>모델 선택 이유 원문</summary>{escape(x.get("question", ""))}</details>'
             for x in row.get("plans", [])]
    facts = [f'<a class="evidence" href="#{page_id(number)}-{escape(x.get("evidence_id", ""))}">{escape(x.get("evidence_id", ""))}</a> '
             f'{escape(ACTIONS.get(x.get("action"), "기타"))} · HTTP {escape(x.get("http_status", ""))}'
             f'<div class="sub">응답 SHA-256: <code>{escape(x.get("body_sha256", ""))}</code></div>'
             for x in row.get("facts", [])]
    findings = [f'<strong>{escape(FINDINGS.get(x.get("kind"), "기타"))}</strong> '
                '<span class="badge warn">수동 확인 필요</span>'
                f'<div>{escape(FINDING_TEXT.get(x.get("kind"), "판단 근거 원문을 확인하세요."))}</div>'
                f'<details class="sub"><summary>판단 근거 원문</summary>{escape(x.get("reason", ""))}</details>'
                '<div class="sub">연결된 증거: ' + (", ".join(
                    f'<a href="#{page_id(number)}-{escape(evidence_id)}">{escape(evidence_id)}</a>'
                    for evidence_id in x.get("evidence_ids", [])) or "연결 없음") + '</div>'
                for x in row.get("findings", [])]
    observations = "".join(
        f'<tr id="{page_id(number)}-obs-{index}"><td><span class="evidence">obs-{index}</span></td>'
        f'<td>{escape(ACTIONS.get(obs.get("action"), "기타"))}</td><td>{escape(obs.get("status", ""))}</td>'
        f'<td>{"예" if obs.get("marker_reflected") else "아니요"}</td>'
        f'<td><pre class="preview">{escape(obs.get("preview", ""))}</pre></td></tr>'
        for index, obs in enumerate(row.get("observations", []), 1))
    obs_table = ('<div class="table-wrap"><table class="table"><thead><tr><th>증거 ID</th><th>요청</th>'
                 '<th>HTTP</th><th>표식 반사</th><th>응답 미리보기</th></tr></thead><tbody>'
                 + observations + '</tbody></table></div>') if observations else '<p class="empty">관찰된 요청이 없습니다.</p>'
    prev = f'<a href="#{page_id(number-1)}">← 이전 페이지</a>' if number > 1 else '<span></span>'
    next_page = f'<a href="#{page_id(number+1)}">다음 페이지 →</a>' if number < total else '<span></span>'
    body = (f'<main id="{page_id(number)}" class="shell detail-page"><header class="top"><a class="brand" href="#dashboard">← 메인 대시보드</a>'
            f'<span class="badge">{number} / {total}</span></header><p class="eyebrow">페이지별 상세 결과</p>'
            f'<h1>페이지 {number:02d}</h1><p class="url"><strong>대상 URL</strong> · <code>{escape(row.get("url", ""))}</code></p>'
            f'<p>{escape(STATES.get(row.get("state"), "기타"))} · {escape(labels(row.get("categories", []), CATEGORIES))}</p>'
            '<div class="notice">모델 계획은 추론이며, 관찰 근거는 HTTP 응답에서 수집했습니다. 수동 확인 대상은 취약점 확정이 아닙니다.</div>'
            '<div class="detail-grid">'
            f'<section class="panel"><h2>URL에서 도출한 테스트 후보</h2>{listing(candidates)}</section>'
            f'<section class="panel"><h2>검토 가설</h2>{listing(hypotheses)}</section>'
            f'<section class="panel"><h2>수동 확인 대상</h2>{listing(findings)}</section>'
            f'<section class="panel"><h2>모델 계획</h2>{listing(plans)}</section>'
            f'<section class="panel"><h2>관찰 근거</h2>{listing(facts)}</section></div>'
            f'<section class="panel"><h2>HTTP 관찰 내역</h2>{obs_table}</section>'
            f'<nav class="nav">{prev}<a href="#dashboard">대시보드로 돌아가기</a>{next_page}</nav></main>')
    return body


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
        if not stream.read("review_report.html"):
            raise RuntimeError("Readable archive verification failed: review_report.html")


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
