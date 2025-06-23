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

## Requirements

- Python 3.7+
- Install dependencies:
  
```bash
pip install -r requirements.txt
