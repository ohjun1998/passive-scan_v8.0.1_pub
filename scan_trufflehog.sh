#!/bin/bash
GROUP_SUFFIX=$1
mkdir -p results

scan_truffle() {
    local dir="$1"
    local group="$2"
    
    [ -d "$dir" ] || return
    
    local basename_dir=$(basename "$dir")
    local safe_domain=${basename_dir%_js_files_*}
    
    echo "[+] [${safe_domain}] [TruffleHog] 파일 내부 기밀 정보 유출 검사 시작..."
    trufflehog filesystem "$dir" --only-verified --json 2>/dev/null > "results/${safe_domain}_trufflehog_raw_${group}.json" || true
    
    if [ -s "results/${safe_domain}_trufflehog_raw_${group}.json" ]; then
        # Never write the detected secret itself to artifacts or reports.
        jq -r '((.SourceMetadata.Data.Filesystem.file // "unknown.js") | split("/") | last) + "\t" + (.DetectorName // "Secret") + "\tverified"' \
          "results/${safe_domain}_trufflehog_raw_${group}.json" > "results/${safe_domain}_trufflehog_${group}.txt" || true
    else
        echo "" > "results/${safe_domain}_trufflehog_${group}.txt"
    fi
    rm -f "results/${safe_domain}_trufflehog_raw_${group}.json"
}
export -f scan_truffle

echo "[*] 오프라인 TruffleHog 스캔 가동..."
for dir in results/*_js_files_${GROUP_SUFFIX}; do
    scan_truffle "$dir" "$GROUP_SUFFIX" &
done
wait
