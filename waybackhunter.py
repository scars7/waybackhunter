import argparse
import csv
import json
import math
import os
import re
import time
import random
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from bs4 import BeautifulSoup
from waybackpy import WaybackMachineCDXServerAPI

# --- Improved Sensitive Patterns ---
SENSITIVE_PATTERNS = {
    "AWS Access Key": r"\bAKIA[0-9A-Z]{16}\b",
    "Google API Key": r"\bAIza[0-9A-Za-z\\-_]{35}\b",
    "Stripe Live Key": r"\bsk_live_[0-9a-zA-Z]{24}\b",
    "OAuth Token": r"\bya29\.[0-9A-Za-z\\-_]{90,}\b",
    "Basic Auth Password": r"(?i)(?:password|passwd|pwd)[\"']?\s*[:=]\s*[\"']([^\"']{8,})[\"']",
    "Generic Secret": r"(?i)\b(?:secret|token|key|credential)[\"']?\s*[:=]\s*[\"']([a-z0-9_\\-]{20,})[\"']"
}

# --- Fixed Entropy Calculation ---
def calculate_entropy(s):
    if not s:
        return 0
    entropy = 0
    for char in set(s):
        p = s.count(char) / len(s)
        entropy -= p * math.log2(p)
    return entropy

def extract_high_entropy_strings(text, threshold=4.5):  # Increased threshold
    words = re.findall(r"\b[a-zA-Z0-9_\\-]{20,}\b", text)
    return [w for w in words if calculate_entropy(w) > threshold]

# --- Robust Wayback Fetching ---
def fetch_urls(domain):
    print(f"[+] Fetching URLs from Wayback Machine for: {domain}")
    try:
        cdx = WaybackMachineCDXServerAPI(
            domain,
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) WayHunter/1.0",
            start_timestamp="2000",
            end_timestamp="2025"
        )
        snapshots = cdx.snapshots()
        return list(set([entry.archive_url for entry in snapshots]))
    except Exception as e:
        print(f"[-] Wayback Machine Error: {e}")
        return []

# --- Scan URL with retries and backoff ---
def scan_url(url, proxies=None, max_retries=3):
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) WayHunter/1.0"}
    attempt = 0

    while attempt < max_retries:
        try:
            resp = requests.get(
                url,
                timeout=15,
                proxies=proxies,
                headers=headers,
                verify=False
            )
            if resp.status_code != 200:
                attempt += 1
                time.sleep(2 ** attempt + random.uniform(0, 1))
                continue
            
            soup = BeautifulSoup(resp.text, "html.parser")
            text = soup.get_text()
            findings = []

            for label, pattern in SENSITIVE_PATTERNS.items():
                for match in re.finditer(pattern, text):
                    secret = match.group(1) if match.lastindex else match.group(0)
                    findings.append({
                        "type": label,
                        "match": secret,
                        "url": url
                    })

            for secret in extract_high_entropy_strings(text):
                findings.append({
                    "type": "High Entropy String",
                    "match": secret,
                    "url": url
                })

            time.sleep(0.5 + random.uniform(0, 0.5))  # Delay between requests
            return findings

        except requests.exceptions.RequestException as e:
            attempt += 1
            print(f"[-] Error scanning {url} (attempt {attempt}/{max_retries}): {str(e)[:100]}")
            time.sleep(2 ** attempt + random.uniform(0, 1))

    print(f"[-] Failed to scan {url} after {max_retries} attempts")
    return []

# --- Fixed Output Handling ---
def save_results(results, output_prefix):
    output_dir = os.path.dirname(output_prefix) or "."
    os.makedirs(output_dir, exist_ok=True)
    
    json_path = f"{output_prefix}.json"
    with open(json_path, 'w') as jf:
        json.dump(results, jf, indent=2)
    
    csv_path = f"{output_prefix}.csv"
    with open(csv_path, 'w', newline='', encoding='utf-8') as cf:
        writer = csv.DictWriter(cf, fieldnames=["type", "match", "url"])
        writer.writeheader()
        for item in results:
            writer.writerow(item)
    
    print(f"\n[+] Results saved to:")
    print(f"    - JSON: {os.path.abspath(json_path)}")
    print(f"    - CSV:  {os.path.abspath(csv_path)}")

# --- Optimized Main Function ---
def main():
    parser = argparse.ArgumentParser(description="WayHunter - Wayback Machine Sensitive Info Scanner")
    parser.add_argument("-d", "--domain", required=True, help="Domain to scan (e.g. example.com)")
    parser.add_argument("-o", "--output", default="results/scan", help="Output file prefix (default: results/scan)")
    parser.add_argument("--threads", type=int, default=4, help="Number of concurrent threads (default: 4)")
    parser.add_argument("--proxy", help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--max-urls", type=int, default=100, help="Maximum URLs to process (default: 100)")
    
    args = parser.parse_args()
    proxies = {"http": args.proxy, "https": args.proxy} if args.proxy else None

    urls = fetch_urls(args.domain)[:args.max_urls]
    print(f"[+] Found {len(urls)} archived URLs to scan")
    
    if not urls:
        print("[-] No URLs found. Exiting.")
        return

    all_findings = []
    completed = 0
    start_time = time.time()
    
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_url = {executor.submit(scan_url, url, proxies): url for url in urls}
        
        for future in as_completed(future_to_url):
            completed += 1
            findings = future.result()
            if findings:
                all_findings.extend(findings)
                
            if completed % 10 == 0 or completed == len(urls):
                elapsed = time.time() - start_time
                print(f"\r[→] Scanned {completed}/{len(urls)} URLs | "
                      f"Found {len(all_findings)} secrets | "
                      f"Elapsed: {elapsed:.1f}s", end="", flush=True)

    print(f"\n[+] Scan complete. Total findings: {len(all_findings)}")
    save_results(all_findings, args.output)

if __name__ == "__main__":
    main()
