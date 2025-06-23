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

# Define regex patterns to detect various sensitive data
SENSITIVE_PATTERNS = {
    "AWS Access Key": r"\bAKIA[0-9A-Z]{16}\b",
    "Google API Key": r"\bAIza[0-9A-Za-z\\-_]{35}\b",
    "Stripe Live Key": r"\bsk_live_[0-9a-zA-Z]{24}\b",
    "OAuth Token": r"\bya29\.[0-9A-Za-z\\-_]{90,}\b",
    "Basic Auth Password": r"(?i)(?:password|passwd|pwd)[\"']?\s*[:=]\s*[\"']([^\"']{8,})[\"']",
    "Generic Secret": r"(?i)\b(?:secret|token|key|credential)[\"']?\s*[:=]\s*[\"']([a-z0-9_\\-]{20,})[\"']"
}

# Calculate Shannon entropy to detect high entropy secrets
def calculate_entropy(s):
    if not s:
        return 0
    entropy = 0
    for char in set(s):
        p = s.count(char) / len(s)
        entropy -= p * math.log2(p)
    return entropy

# Extract high entropy strings as potential secrets
def extract_high_entropy_strings(text, threshold=4.5):
    words = re.findall(r"\b[a-zA-Z0-9_\\-]{20,}\b", text)
    return [w for w in words if calculate_entropy(w) > threshold]

# Fetch archived URLs using Wayback Machine CDX API
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

# Scan a single URL for secrets with retry logic
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
                verify=False  # Disable SSL verification (for controlled scanning only)
            )
            if resp.status_code != 200:
                attempt += 1
                time.sleep(2 ** attempt + random.uniform(0, 1))
                continue
            
            soup = BeautifulSoup(resp.text, "html.parser")
            text = soup.get_text()
            findings = []

            # Match based on sensitive regex patterns
            for label, pattern in SENSITIVE_PATTERNS.items():
                for match in re.finditer(pattern, text):
                    secret = match.group(1) if match.lastindex else match.group(0)
                    findings.append({
                        "type": label,
                        "match": secret,
                        "url": url
                    })

            # Match high entropy strings
            for secret in extract_high_entropy_strings(text):
                findings.append({
                    "type": "High Entropy String",
                    "match": secret,
                    "url": url
                })

            time.sleep(0.5 + random.uniform(0, 0.5))  # Throttle requests slightly
            return findings

        except requests.exceptions.RequestException as e:
            attempt += 1
            print(f"[-] Error scanning {url} (attempt {attempt}/{max_retries}): {str(e)[:100]}")
            time.sleep(2 ** attempt + random.uniform(0, 1))

    print(f"[-] Failed to scan {url} after {max_retries} attempts")
    return []

# Save the scan output in both JSON and CSV formats
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

# Main execution logic
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

