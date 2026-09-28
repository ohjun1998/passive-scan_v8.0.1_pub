# Passive Scan v8.0.1

v8의 GitHub Actions 분산 정찰 구조를 유지하면서 수집 누락과 보고서 해석 오류를 고친 버전입니다. 원본 v8 저장소는 수정하지 않았습니다.

## 실행

Repository Settings → Secrets and variables → Actions에 값을 설정합니다.

| Secret | 값 |
|---|---|
| `TARGET_DOMAINS` | 줄 단위 대상 호스트. `example.com` 또는 `*.example.com` |
| `ACTIONS_CRYPTO_PASSWORD` | 결과 압축 파일의 암호 |
| `DISCORD_WEBHOOK_URL` | 완료 알림용. 사용하지 않으면 비워둠 |
| `GEMINI_API_KEY` | 선택적 AI 우선순위 분석용. 사용하지 않으면 비워둠 |

Actions → **Automated Parallel Passive Reconnaissance** → **Run workflow**를 실행합니다.
예약 실행은 설정되어 있지 않습니다. 대상에 Katana, httpx, gowitness, JS 다운로드 및 서브도메인 상태 확인 요청이 발생하므로 허가된 범위에서만 실행하세요.

완료 후 `passive-recon-master-report-secured` artifact를 다운로드하고 `ACTIONS_CRYPTO_PASSWORD`로 압축을 해제하면 Excel, SQLite, Postman, 화면 갤러리가 있습니다. 다음 실행은 이전 보고서의 SQLite 이력을 가져옵니다. 최종 artifact 보존 기간은 14일이므로 누적 이력이 필요하면 별도로 보관해야 합니다.

## v8.0.1 개선 내용

- Katana URL을 httpx 입력까지 전달하고, 비슷한 URL 5개 초과분도 원본 그대로 보존합니다.
- 이전 SQLite의 URL을 복원하고 현재 대상 범위에 다시 맞는 것만 검사합니다.
- JS URL의 쿼리를 보존하며 URL·본문 SHA-256을 파일명에 넣어 같은 `app.js` 충돌을 막습니다. 매 실행 다시 다운로드하므로 수정된 JS가 재분석됩니다. 노드당 1000개가 상한입니다.
- TruffleHog 결과는 검증된 탐지기의 이름과 JS 출처만 보고서에 넣습니다. 비밀값 원문은 결과 텍스트와 Excel에 넣지 않고, 탐지 결과를 URL로 오해하지 않도록 별도 Secrets 시트를 만듭니다.
- 응답 결과가 없는 URL은 `NotProbed`, 검사 결과에 상태 코드가 없는 경우는 `ProbeError`로 표시합니다. 지난 실행과 HTTP 상태가 다르면 Status Changes 시트에 기록합니다.
- Gemini를 선택해 사용할 때 URL 전체 대신 불투명 ID, 경로 패턴, 쿼리 **키 이름**만 보냅니다. 점수는 취약점 확률이 아니라 수동 점검 우선순위입니다.
- Review Queue 시트가 SQLite의 수동 검토 상태를 표시합니다. 결과의 Postman GET은 URL만으로 추정한 것이므로 실제 요청 메서드와 인증 조건을 확인하세요.

## 수동 검토 상태

보고서 DB와 `review.py`를 같은 작업 디렉터리에 두고 실행합니다.

```bash
python review.py 'https://example.com/api/users/123' --status investigating --owner analyst --note '계정 간 소유권 비교'
```

상태: `unreviewed`, `investigating`, `false_positive`, `reported`. CLI는 SQLite를 수정합니다. 다음 보고서 생성 시 Review Queue에 반영되며, 다음 Actions 실행에서 이 상태를 이어가려면 수정된 `recon_history.db`를 기존 보고서 압축 파일에 다시 넣어 복원 가능한 위치에 보관해야 합니다. Actions artifact 자체는 소급 변경되지 않습니다.

## 검증

```bash
python -m unittest discover -s tests -v
python -m py_compile js_assets.py global_mixer.py txt_to_excel.py review.py
bash -n collect_urls.sh scan_linkfinder.sh scan_trufflehog.sh
```

테스트는 로컬 파일과 모의 응답만 사용합니다. 전체 GitHub Actions 실행, 외부 도구 설치, 실제 대상 및 Gemini 분석은 여기서 검증하지 않았습니다.

## 남은 한계

이 버전은 20개 병렬 작업의 도메인별 총 요청 예산을 강제하지 않습니다. URL에서 추정한 Postman 메서드, JS의 상대 경로, AI 우선순위는 수동 확인이 필요합니다. URL 쿼리에는 민감한 값이 들어갈 수 있으므로 원본 DB·보고서·암호화 artifact를 제한적으로 관리하세요. 기존 ZIP 암호 방식도 강한 암호화 수단으로 간주하지 마세요.
