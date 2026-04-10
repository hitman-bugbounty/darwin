# XSS Hunter Pro

**Automated XSS Vulnerability Scanner** by **RootDR**

> Crawl + Discover + Reflect + Exploit + Verify

[![Twitter](https://img.shields.io/badge/Twitter-@R00tDR-1DA1F2?style=flat&logo=x)](https://x.com/R00tDR)
[![Telegram](https://img.shields.io/badge/Telegram-@RootDR-2CA5E0?style=flat&logo=telegram)](https://t.me/RootDR)

Advanced automated XSS vulnerability scanner for bug bounty hunters and penetration testers. Combines recursive web crawling, parameter discovery, context-aware payload testing, and DOM XSS detection in a single CLI tool.

## Features

- **Recursive web crawling** with built-in crawler (optional [Katana](https://github.com/projectdiscovery/katana) integration for faster crawling)
- **Parameter discovery** from URLs, HTML forms, JavaScript, and brute-force probing of 60+ common parameter names
- **Context-aware XSS payloads** — HTML, attribute, script, URL, polyglot, mutation, and WAF-bypass variants
- **DOM XSS detection** — static analysis of source-to-sink patterns (`location.hash` → `innerHTML`, `document.write`, `eval`, etc.)
- **Reflected XSS testing** for both GET and POST parameters
- **Blind XSS support** with configurable callback domains
- **Header injection testing** across 12 common reflectable headers (Referer, X-Forwarded-For, etc.)
- **Browser-based verification** using headless Chrome (optional)
- **Connection pooling** with automatic retry and exponential backoff
- **User-Agent rotation** to avoid fingerprinting
- **URL-pattern normalisation** — automatically deduplicates URL variations (e.g. `/course/123` and `/course/456`) so the same endpoint is only tested once
- **Thread-safe** concurrent scanning with result deduplication
- **Confidence scoring** (0–100%) for each finding
- **JSON and text reports** generated automatically

## Installation

```bash
git clone https://github.com/rootdr-backup/xss-hunter.git
cd xss-hunter
pip install -r requirements.txt
```

### Optional: Install Katana (faster crawling)

The tool works without Katana using its built-in recursive crawler, but Katana provides faster and more thorough crawling:

```bash
go install github.com/projectdiscovery/katana/cmd/katana@latest
```

## Quick Start

```bash
# Basic scan
python3 xss_hunter_pro.py -t https://target.com
```

## Usage

```
python3 xss_hunter_pro.py -t <target_url> [options]
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-t`, `--target` | Target URL to scan (required) | — |
| `-d`, `--depth` | Crawl depth | `4` |
| `--threads` | Number of concurrent threads | `50` |
| `--delay` | Delay between requests (seconds) | `0.1` |
| `--timeout` | Request timeout (seconds) | `15` |
| `--max-urls` | Maximum URLs to crawl | `10000` |
| `--headless` | Enable headless browser crawling | off |
| `--chrome-path` | Path to Chrome executable | macOS default |
| `--blind-callback` | Blind XSS callback domain (e.g., `xss.ht`) | — |
| `--no-headers` | Skip header injection testing | off |
| `--no-brute` | Skip common parameter brute-forcing | off |
| `--nodom` | Skip DOM XSS scanning (faster scans) | off |
| `--output` | Output directory for reports | `xss_results` |
| `-v`, `--verbose` | Verbose output (DEBUG logging) | off |

### Examples

```bash
# Fast scan with fewer threads and shallow depth
python3 xss_hunter_pro.py -t https://target.com -d 2 --threads 10

# Deep scan
python3 xss_hunter_pro.py -t https://target.com -d 8 --threads 30

# With blind XSS callback
python3 xss_hunter_pro.py -t https://target.com --blind-callback your-callback.xss.ht

# Skip header testing and brute-force for speed
python3 xss_hunter_pro.py -t https://target.com --no-headers --no-brute

# Skip DOM XSS scanning (useful for large sites)
python3 xss_hunter_pro.py -t https://target.com --nodom

# Verbose output for debugging
python3 xss_hunter_pro.py -t https://target.com -v

# Fast scan (fewer threads, shallow depth)
python3 xss_hunter_pro.py -t https://target.com -d 2 --threads 100

# Deep scan with headless browser
python3 xss_hunter_pro.py -t https://target.com -d 8 --threads 30 --headless
```

## How It Works

The scanner runs through 7 phases:

1. **Crawling** — Discovers URLs via Katana or the built-in recursive crawler. Extracts links, forms, and JavaScript references.
2. **Parameter Discovery** — Collects GET/POST parameters from crawled URLs, HTML forms, and inline JavaScript. Optionally brute-forces 60+ common parameter names.
3. **Reflection Testing** — Injects a unique marker into each parameter (GET and POST) to identify which ones reflect user input in the response.
4. **Header Injection Testing** — Tests 12 common HTTP headers for reflection (Referer, X-Forwarded-For, X-Real-IP, etc.).
5. **XSS Payload Testing** — Sends context-aware payloads (HTML, attribute, script, URL, polyglot, mutation, WAF-bypass) against all reflected parameters. Calculates confidence scores based on how the payload appears in the response.
6. **DOM XSS Analysis** — Performs static analysis on page source to detect dangerous source→sink patterns (e.g., `location.hash` piped into `innerHTML` or `document.write`).
7. **Browser Verification** (optional) — Uses headless Chrome to confirm XSS findings by checking for actual JavaScript execution.

## Output

Results are saved to the `xss_results/` directory (configurable with `--output`):

- **`xss_report_<timestamp>.json`** — Machine-readable JSON report with all findings, metadata, and confidence scores.
- **`xss_report_<timestamp>.txt`** — Human-readable text report with a summary table and detailed vulnerability entries.

### JSON Report Structure

```json
{
  "target": "https://target.com",
  "scan_date": "2026-04-09T18:14:57",
  "total_urls": 7,
  "total_parameters": 14,
  "summary": {
    "total_xss": 22,
    "high_confidence": 21,
    "reflected": 7,
    "dom": 8,
    "blind": 0
  },
  "vulnerabilities": [
    {
      "url": "https://target.com/search",
      "parameter": "q",
      "payload": "<script>alert('XSSHUNTERPROTEST')</script>",
      "type": "reflected",
      "context": "html",
      "method": "GET",
      "confidence": 95,
      "evidence": "...",
      "timestamp": "2026-04-09T18:14:32"
    }
  ]
}
```

## Payloads

The tool ships with 45+ built-in payloads covering:

- Basic HTML injection (`<script>`, `<img onerror>`, `<svg onload>`)
- Attribute context breaks (`" onmouseover=`, `' onfocus=`)
- Script context breaks (`'-alert()-'`, `</script><script>`)
- URL context (`javascript:`, `data:`)
- Polyglot payloads (work across multiple contexts)
- Mutation XSS (`<math><mtext>` tree confusion)
- WAF bypass variants (case mixing, encoding, null bytes, tag nesting)
- Blind XSS with configurable callback

An extended payload database is also available in `payloads_advanced.txt` (420+ payloads).

## Requirements

- Python 3.8+
- See [requirements.txt](requirements.txt) for Python dependencies
- Optional: [Katana](https://github.com/projectdiscovery/katana) for faster crawling
- Optional: Google Chrome/Chromium for browser-based verification

## Disclaimer

This tool is intended for authorized security testing only. Always obtain proper authorization before scanning any target. The authors are not responsible for any misuse or damage caused by this tool. Use responsibly and in compliance with all applicable laws.

## License

This project is provided as-is for educational and authorized security testing purposes.
