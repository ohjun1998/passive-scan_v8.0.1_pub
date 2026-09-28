#!/bin/bash

# $1 인자가 없으면 기본값(00) 할당
GROUP=${1:-"00"}
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
  # 대상 서버에 직접 접근하는 크롤링은 운영 안전 정책에 따라 중지합니다.
  # 아카이브 제공자에서만 URL을 수집합니다.
  # ---------------------------------------------------------
  # 두 외부 아카이브 수집기의 종료를 기다립니다.
  # ---------------------------------------------------------
  wait
  echo "  [*] ✅ 해당 서브도메인 묶음의 딥 스캔 완료!"

  # ---------------------------------------------------------
  # 5. JS URL 목록만 저장합니다. 실제 JS 파일은 다운로드하지 않습니다.
  # ---------------------------------------------------------
  echo "  [+] ⚙️ 수집된 전체 데이터에서 JavaScript(JS) 타겟 추출 중..."
  cat "results/${SAFE_DOMAIN}_"*"_${GROUP}.txt" 2>/dev/null | grep -iE '\.m?js($|\?)' | sort -u > "results/${SAFE_DOMAIN}_js_targets.txt" || true
  JS_TOTAL=$(wc -l < "results/${SAFE_DOMAIN}_js_targets.txt" 2>/dev/null || echo 0)

  echo "  [+] JS URL ${JS_TOTAL}개 기록 완료 (직접 다운로드 없음)."

done

echo "==================================================================="
echo "🏁 [Node-$GROUP] 도메인 수집 프로세스 종료"
echo "==================================================================="
