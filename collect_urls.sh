#!/bin/bash

# $1 인자가 없으면 기본값(00) 할당
GROUP=${1:-"00"}
SCAN_MODE=${SCAN_MODE:-"full"}
TARGETS_FILE="targets.txt"

if [ ! -f "$TARGETS_FILE" ]; then
  echo "[-] $TARGETS_FILE 파일이 존재하지 않습니다."
  exit 1
fi

mkdir -p results

echo "==================================================================="
echo "🚀 [Node-$GROUP] 정찰 파이프라인 가동 (MapReduce 기반 분산 스캔)"
echo "==================================================================="

# 1. 태그(SAFE_DOMAIN)를 기준으로 타겟들을 분리 저장 (동시 파일 접근 충돌 방지)
awk -F':' '{print $2 > "results/"$1"_all_targets.txt"}' $TARGETS_FILE

for TARGET_FILE in results/*_all_targets.txt; do
  [ -e "$TARGET_FILE" ] || continue
  
  BASENAME=$(basename "$TARGET_FILE")
  SAFE_DOMAIN=${BASENAME%_all_targets.txt}
  
  echo "=================================================="
  echo "🎯 [Target: $SAFE_DOMAIN] 할당된 서브도메인 병렬 스캔 가동"
  echo "=================================================="

  # ---------------------------------------------------------
  # 2. Waybackurls (과거 아카이브 URL 병렬 추출)
  # ---------------------------------------------------------
  (
    echo "  [+] 🏛️ [Waybackurls] 병렬 추출 중..."
    cat "$TARGET_FILE" | waybackurls | uro > "results/${SAFE_DOMAIN}_waybackurls_${GROUP}.txt" 2>/dev/null || true
  ) &

  # ---------------------------------------------------------
  # 3. GAU (외부 위협 인텔리전스 기반)
  # ---------------------------------------------------------
  (
    echo "  [+] 🌐 [GAU] 위협 인텔리전스 추출 중..."
    cat "$TARGET_FILE" | gau --threads 5 | uro > "results/${SAFE_DOMAIN}_gau_${GROUP}.txt" 2>/dev/null || true
  ) &

  # ---------------------------------------------------------
  # 전체 검사 모드에서 원래 속도로 크롤링합니다.
  # ---------------------------------------------------------
  if [ "$SCAN_MODE" = "full" ]; then
    (
      echo "  [+] [Katana] 크롤링 중..."
      katana -list "$TARGET_FILE" -d 2 -c 5 -rl 50 -jc -silent | uro > "results/${SAFE_DOMAIN}_katana_${GROUP}.txt" 2>/dev/null || true
    ) &
  fi

  # 병렬 수집기가 끝날 때까지 대기합니다.
  # ---------------------------------------------------------
  wait
  echo "  [*] ✅ 해당 서브도메인 묶음의 딥 스캔 완료!"

  # ---------------------------------------------------------
  # 5. JS URL 목록을 만들고 전체 검사일 때 분석용 파일을 내려받습니다.
  # ---------------------------------------------------------
  echo "  [+] ⚙️ 수집된 전체 데이터에서 JavaScript(JS) 타겟 추출 중..."
  cat "results/${SAFE_DOMAIN}_"*"_${GROUP}.txt" 2>/dev/null | grep -iE '\.m?js($|\?)' | sort -u > "results/${SAFE_DOMAIN}_js_targets.txt" || true
  JS_TOTAL=$(wc -l < "results/${SAFE_DOMAIN}_js_targets.txt" 2>/dev/null || echo 0)

  echo "  [+] JS URL ${JS_TOTAL}개 기록 완료."
  if [ "$SCAN_MODE" = "full" ] && [ "$JS_TOTAL" -gt 0 ]; then
    python3 js_assets.py "results/${SAFE_DOMAIN}_js_targets.txt" "results/${SAFE_DOMAIN}_js_files_${GROUP}" "results/${SAFE_DOMAIN}_js_mapping_${GROUP}.txt" || true
  fi

done

echo "==================================================================="
echo "🏁 [Node-$GROUP] 도메인 수집 프로세스 종료"
echo "==================================================================="
