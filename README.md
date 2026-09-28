# Passive Scan v8.0.1

v8의 20개 병렬 정찰 구조와 URL별 응답 검사를 사용하는 버전입니다. HTTP 검사에서는 같은 호스트가 여러 작업에 중복 배정되지 않도록 URL을 호스트별로 묶습니다. 원본 v8 저장소는 수정하지 않았습니다.

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
| `full` (기본값) | Katana 크롤링, JS 다운로드, 수집된 URL의 HTTP 검사 | 이전처럼 최대 20개 작업에서 병렬 검사. 각 HTTP 검사 작업은 최대 초당 10회, 동시 연결 5개, 타임아웃 5초, 재시도 1회 |
| `collect` | 코드가 직접 보내는 요청 0회 | Subfinder, GAU, Waybackurls 등 외부 제공자의 공개 정보 수집. 상태는 `NotProbed` |
| `bounded-probe` | 수집된 호스트 중 최대 20개에 HTTPS `/` HEAD 요청 각 1회, 작업 전체 2초 간격, 5초 시간 제한, 재시도 및 리다이렉트 없음 | 첫 화면 응답 코드만 기록. HTTP 429 또는 5xx 응답 시 나머지 검사 중단 |

`full`에서 **screenshots** 옵션은 기본적으로 꺼져 있습니다. 켜면 20개 작업에서 브라우저 캡처가 추가되어 페이지의 JavaScript와 하위 리소스 요청이 발생할 수 있습니다. 예약 실행은 설정되어 있지 않습니다. 같은 저장소의 중복 워크플로 실행은 concurrency로 제한됩니다. 허용 목록은 `TARGET_DOMAINS`입니다.

운영 서비스에서 `full`을 사용할 때는 대상 소유자와 실행 시간·허용 트래픽을 합의하세요. HTTP 검사 단계의 최대 요청 속도는 **작업당 초당 10회, 작업 전체 이론상 초당 200회**이며 Katana(작업당 최대 초당 50회)와 JS 다운로드는 이 한도에 포함되지 않습니다. 여러 호스트가 같은 백엔드를 공유한다면 호스트별 분배만으로 백엔드 총량을 제어할 수 없습니다. GET 요청도 기능에 따라 데이터를 변경할 수 있으므로 수집된 경로를 자동 검사해도 안전하다고 보장할 수 없습니다. 429/503이나 오류율이 늘면 Actions 실행을 중단하세요.

완료 후 `passive-recon-master-report-secured` artifact를 다운로드하고 `ACTIONS_CRYPTO_PASSWORD`로 압축을 해제하면 Excel, SQLite, Postman, 화면 갤러리가 있습니다. 스크린샷을 선택하지 않았다면 화면 이미지 없이 갤러리 틀만 생성됩니다. 다음 실행은 이전 보고서의 SQLite 이력을 가져옵니다. 최종 artifact 보존 기간은 14일이므로 누적 이력이 필요하면 별도로 보관해야 합니다.

## v8.0.1 개선 내용

- 외부 아카이브와 Katana가 반환한 URL을 기록하며, `full`에서는 블랙리스트 및 정적 파일 필터를 통과한 URL 전체를 HTTP 검사의 입력으로 전달합니다. 같은 호스트의 URL은 한 작업에만 들어갑니다.
- 이전 SQLite의 URL을 복원하고 현재 대상 범위에 맞는 URL만 다시 검사합니다.
- `full`에서는 JS URL의 쿼리를 보존해 파일을 다시 다운로드하고 분석합니다. 각 대상 묶음당 최대 1000개입니다. TruffleHog 비밀값 원문은 보고서에 넣지 않습니다.
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

`full`은 URL 개수의 상한을 두지 않으므로 한 호스트의 URL이 매우 많으면 해당 작업이 GitHub Actions의 개별 작업 6시간 제한을 넘을 수 있습니다. Katana와 JS 다운로드 및 선택형 브라우저 캡처에는 전체 워크플로를 가로지르는 요청 예산이 없습니다. `collect`에서도 외부 공개 정보 제공자가 자체적으로 어떻게 자료를 수집했는지 이 코드가 통제할 수 없습니다. URL에서 추정한 Postman 메서드, AI 우선순위는 수동 확인이 필요합니다. URL 쿼리에는 민감한 값이 들어갈 수 있으므로 원본 DB·보고서·암호화 artifact를 제한적으로 관리하세요. 기존 ZIP 암호 방식도 강한 암호화 수단으로 간주하지 마세요.
