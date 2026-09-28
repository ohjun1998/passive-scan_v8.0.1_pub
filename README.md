# Passive Scan v8.0.1

v8의 공개 자료 수집 및 보고서 생성 구조를 유지하면서 운영 서비스에 대한 직접 요청을 기본적으로 차단한 버전입니다. 원본 v8 저장소는 수정하지 않았습니다.

## 실행

Repository Settings → Secrets and variables → Actions에 값을 설정합니다.

| Secret | 값 |
|---|---|
| `TARGET_DOMAINS` | 줄 단위 대상 호스트. `example.com` 또는 `*.example.com` |
| `ACTIONS_CRYPTO_PASSWORD` | 결과 압축 파일의 암호 |
| `DISCORD_WEBHOOK_URL` | 완료 알림용. 사용하지 않으면 비워둠 |
| `GEMINI_API_KEY` | 선택적 AI 우선순위 분석용. 사용하지 않으면 비워둠 |

Actions → **Automated Parallel Passive Reconnaissance** → **Run workflow**에서 모드를 선택합니다.

| 모드 | 운영 서비스에 발생하는 직접 요청 | 결과 |
|---|---|---|
| `collect` (기본값) | 코드가 직접 보내는 요청 0회 | Subfinder, GAU, Waybackurls 등 외부 제공자의 공개 정보 수집. 상태는 `NotProbed` |
| `bounded-probe` (명시적 선택) | 수집된 호스트 중 최대 20개에 HTTPS `/` HEAD 요청 각 1회, 작업 전체 2초 간격, 5초 시간 제한, 재시도 및 리다이렉트 없음 | 첫 화면 응답 코드만 기록. HTTP 429 또는 5xx 응답 시 나머지 검사 중단 |

예약 실행은 설정되어 있지 않습니다. `bounded-probe`도 운영 서비스에 직접 접근하므로, 대상 소유자와 운영 담당자의 허용 범위·실행 시간에 맞춰 사용하세요. 같은 저장소의 중복 실행은 workflow concurrency로 제한됩니다. 허용 목록은 `TARGET_DOMAINS`이며, 후보가 20개를 넘으면 이름순 앞의 20개만 검사합니다. 발견된 API URL은 직접 호출하지 않습니다.

완료 후 `passive-recon-master-report-secured` artifact를 다운로드하고 `ACTIONS_CRYPTO_PASSWORD`로 압축을 해제하면 Excel, SQLite, Postman, 화면 갤러리 틀이 있습니다. 자동 브라우저 캡처는 비활성화되어 이미지가 생성되지 않습니다. 다음 실행은 이전 보고서의 SQLite 이력을 가져옵니다. 최종 artifact 보존 기간은 14일이므로 누적 이력이 필요하면 별도로 보관해야 합니다.

## v8.0.1 개선 내용

- 외부 아카이브가 반환한 URL을 개수 제한 없이 기록합니다. Katana 크롤링과 JS 직접 다운로드는 실행하지 않습니다.
- 이전 SQLite의 URL을 복원해 현재 대상 범위의 URL만 보고서에 반영합니다. API 경로와 쿼리는 자동 호출하지 않습니다.
- JS URL 목록은 보관하지만 파일을 내려받지 않으므로 새 JS 분석 및 TruffleHog 탐지는 실행되지 않습니다. 과거 결과가 복원된 경우 비밀값 원문 없이 별도 Secrets 시트에 표시합니다.
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
python -m py_compile js_assets.py global_mixer.py safe_probe.py txt_to_excel.py review.py
bash -n collect_urls.sh scan_linkfinder.sh scan_trufflehog.sh
```

테스트는 로컬 파일과 모의 응답만 사용합니다. 전체 GitHub Actions 실행, 외부 도구 설치, 실제 대상 및 Gemini 분석은 여기서 검증하지 않았습니다.

## 운영 시 한계

요청을 20회 이하로 제한해도 서비스 가용성을 보장할 수는 없습니다. 프록시·CDN·모니터링·애플리케이션이 HEAD를 GET처럼 처리할 수도 있고, 별도 시스템의 트래픽과 합쳐질 수 있습니다. `collect`에서도 외부 공개 정보 제공자가 자체적으로 어떻게 자료를 수집했는지 이 코드가 통제할 수는 없습니다. 대상의 서버 로그와 오류율을 살피고 필요한 경우 Actions 실행을 중단하세요. URL에서 추정한 Postman 메서드, AI 우선순위는 수동 확인이 필요합니다. URL 쿼리에는 민감한 값이 들어갈 수 있으므로 원본 DB·보고서·암호화 artifact를 제한적으로 관리하세요. 기존 ZIP 암호 방식도 강한 암호화 수단으로 간주하지 마세요.
