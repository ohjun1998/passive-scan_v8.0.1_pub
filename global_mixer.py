#!/usr/bin/env python3
import os
import glob
import re
import posixpath
import sqlite3
from urllib.parse import urlparse, parse_qsl

def make_absolute(url, domain):
    if url.startswith('http://') or url.startswith('https://'): return url
    elif url.startswith('//'): return f"https:{url}"
    elif url.startswith('/'): return f"https://{domain}{url}"
    else: return f"https://{domain}/{url}"

def get_safe_domain(target):
    return "wild_" + target[2:] if target.startswith('*.') else target

def normalize_dynamic_path(path):
    p = re.sub(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}', '{UUID}', path)
    p = re.sub(r'\b\d{3,}\b', '{ID}', p)
    p = re.sub(r'\b[a-zA-Z0-9]{10,}\b', '{HASH}', p)
    return p

def run_mixer():
    print("[+] 글로벌 셔플 엔진 가동 (과거 DB 통합 및 Httpx 재검증 준비)...")
    if not os.path.exists('targets.txt'): return
    
    with open('targets.txt', 'r') as f:
        targets = [line.strip() for line in f if line.strip()]

    target_map = {get_safe_domain(t): t for t in targets}

    js_url_converter = {}
    for mf in glob.glob('results/*_js_mapping.txt'):
        try:
            with open(mf, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    if '\t' in line:
                        s, o = line.strip().split('\t', 1)
                        js_url_converter[s] = o
        except: pass

    all_urls = set()
    txt_files = glob.glob('results/**/*.*', recursive=True) + glob.glob('results/*.*')
    
    for file_path in txt_files:
        if not os.path.isfile(file_path): continue
        filename = os.path.basename(file_path).lower()
        match = re.match(r'^(.*)_(linkfinder|gau|waybackurls|katana)(?:_[0-9]{2})?\.txt$', filename)
        if not match: continue
        
        safe_domain = match.group(1)
        if safe_domain not in target_map: continue
        
        raw_target = target_map[safe_domain]
        is_wildcard = raw_target.startswith('*.')
        base_domain = raw_target[2:] if is_wildcard else raw_target

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line_str = line.strip()
                    if not line_str or line_str.startswith('#'): continue
                    line_str = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]', '', line_str)
                    if not line_str: continue

                    if '\t' in line_str: raw_url = line_str.split('\t', 1)[1]
                    else: raw_url = line_str

                    abs_url = make_absolute(raw_url, base_domain)
                    parsed_netloc = urlparse(abs_url).netloc.split(':')[0]
                    
                    if is_wildcard:
                        if not (parsed_netloc == base_domain or parsed_netloc.endswith('.' + base_domain)):
                            continue
                    else:
                        if parsed_netloc != base_domain:
                            continue
                            
                    all_urls.add(abs_url)
        except: pass

    # Restore the actual report database; the old text filename was not in the artifact.
    prev_db_path = 'previous_report/recon_history.db'
    if os.path.exists(prev_db_path):
        try:
            print("[*] 이전 스캔 DB의 URL을 현재 범위 안에서 재검사합니다...")
            with sqlite3.connect(prev_db_path) as conn:
                all_urls.update(row[0] for row in conn.execute("SELECT url FROM master_urls"))
        except Exception as e:
            print(f"[-] 텍스트 DB 합류 실패: {e}")

    junk_exts = ('.png', '.jpg', '.jpeg', '.gif', '.svg', '.css', '.woff', '.woff2', '.ico', '.eot', '.ttf', '.mp4')
    blacklist_words = ['logout', 'signout', 'delete', 'remove', 'revoke', 'destroy']
    
    valid_targets = []
    
    for u in all_urls:
        parsed = urlparse(u)
        host = parsed.hostname or ''
        if parsed.scheme not in ('http', 'https') or parsed.username or parsed.password:
            continue
        if not any(
            host == target[2:] or host.endswith('.' + target[2:])
            if target.startswith('*.') else host == target
            for target in targets
        ):
            continue
        
        if parsed.path.lower().endswith(junk_exts): continue
        url_lower = u.lower()
        if any(b in url_lower for b in blacklist_words): continue
            
        # Preserve every original URL. Grouping for display must not discard probes.
        valid_targets.append(u)

    # Report storage keeps all discovered URLs. Only bare HTTPS roots can be
    # passed to the optional, globally bounded HEAD probe.
    hosts = {urlparse(u).hostname for u in valid_targets}
    for path in glob.glob('results/*_all_targets.txt'):
        for line in open(path, encoding='utf-8', errors='ignore'):
            hosts.add(line.strip().lower())
    roots = sorted(
        f'https://{host}/' for host in hosts if host and
        re.fullmatch(r'[a-z0-9][a-z0-9.-]*[a-z0-9]', host) and
        any(host == target[2:] or host.endswith('.' + target[2:])
            if target.startswith('*.') else host == target for target in targets)
    )
    # Fixed ceiling: a workflow input cannot raise it accidentally.
    selected = roots[:20]
    os.makedirs('chunks', exist_ok=True)
    with open('chunks/chunk_00.txt', 'w') as f:
        f.writelines(url + '\n' for url in selected)
    print(f"[+] URL {len(valid_targets)}개 기록, HEAD 후보 {len(selected)}개 / 전체 {len(roots)}개 호스트")

if __name__ == '__main__':
    run_mixer()
