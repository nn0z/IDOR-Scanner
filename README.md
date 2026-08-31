## IDOR-Scanner
An automated security discovery engine built with Python and Playwright to detect Insecure Direct Object Reference (IDOR) vulnerabilities across web applications, query parameters, path structures, and POST forms.

## Features
* **Automated Discovery:** Crawls target websites, extracts unique internal links, parses dynamic JavaScript files, and detects internal API endpoints (`/api/`, `/v1/`, `/rest/`).
* **Multi-Vector Testing:** Automatically tests numeric parameters across query parameters, URL path structures, and form submission fields.
* **Smart Validation Engine:** Filters out public and error pages via comprehensive keyword matching and regular expressions to separate genuine IDOR vulnerabilities from false positives.
* **Real-Time Telegram Alerts:** Instantly sends high-priority notifications to a configured Telegram bot the moment a real vulnerability is identified.
* **Terminal Summary Reports:** Renders clean, color-coded console layouts alongside comprehensive security score metrics upon scan completion.

## Telegram Integration
The tool supports instant notifications via Telegram. To enable real-time alerts when vulnerabilities are detected, configure your bot credentials directly inside the script:
```python
TELEGRAM_BOT_TOKEN = "YOUR_BOT_TOKEN_HERE"
TELEGRAM_CHAT_ID = "YOUR_CHAT_ID_HERE"

```

## Prerequisites
Ensure you have Python installed on your system. The tool requires the following Python libraries:
* `requests`
* `playwright`

After installing playwright, make sure to install the browser drivers:
```bash
playwright install chromium
```

## Disclaimer
This tool is created for educational purposes, authorized security assessments, and Bug Bounty programs only.
The developer assumes no liability and is not responsible for any misuse or damage caused by this program.
Use responsibly and only on targets you have explicit permission to test.
