# WayHunter 
WayHunter is a powerful Python-based tool designed to discover exposed secrets and sensitive information from archived web pages using the Wayback Machine (web.archive.org). This is useful for security researchers, penetration testers, and bug bounty hunters who want to analyze historical versions of web applications for leaked credentials or tokens.

##  Features

- Fetches archived URLs from the [Wayback Machine](https://archive.org/web/)
- Scans each page for:
  - API keys (Google, AWS, Stripe, etc.)
  - OAuth tokens
  - High-entropy secrets (like access tokens or passwords)
- Uses regex and entropy-based analysis
- Multi-threaded scanning for speed
- Outputs findings to `.json` and `.csv` formats
- Proxy support for routing through tools like Burp Suite

 ## Options
 
| Flag         | Description                                         |
| ------------ | --------------------------------------------------- |
| `-d`         | Target domain (required)                            |
| `-o`         | Output file prefix (default: `results/scan`)        |
| `--threads`  | Number of parallel threads (default: 8)             |
| `--max-urls` | Maximum number of archived URLs to scan             |
| `--proxy`    | Optional HTTP proxy (e.g., `http://127.0.0.1:8080`) |

 ## Example
``` python wayback.py -d example.com -o results/wakatime --threads 4 --max-urls 100

Legal Disclaimer
This tool is intended for educational purposes and authorized testing only. Do not scan domains you do not own or have explicit permission to assess.

