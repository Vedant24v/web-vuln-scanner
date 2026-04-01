# 🔍 Web Vulnerability Scanner

A Python-based command-line tool that automatically scans web applications for common security vulnerabilities based on the **OWASP Top 10**. Generates a detailed HTML report of all findings.

---

## 🚀 Features

- ✅ **Missing Security Headers** — Detects absence of CSP, X-Frame-Options, HSTS, and more
- ✅ **Reflected XSS Detection** — Injects payloads into URL parameters and checks for reflection
- ✅ **SQL Injection Detection** — Identifies database errors triggered by malicious input
- ✅ **Severity Ratings** — Findings classified as CRITICAL / HIGH / MEDIUM
- ✅ **HTML Report Generation** — Clean, timestamped report saved locally
- ✅ **Color-coded Terminal Output** — Real-time results using the `rich` library

---

## 🛠️ Tech Stack

- **Language:** Python 3.x
- **Libraries:** `requests`, `beautifulsoup4`, `rich`
- **Concepts:** OWASP Top 10, HTTP headers, XSS, SQL Injection, Security Automation

---

## 📁 Project Structure
```
web-vuln-scanner/
│
├── scanner/
│   ├── __init__.py       # Module init
│   ├── headers.py        # Security header checks
│   ├── xss.py            # Reflected XSS detection
│   ├── sqli.py           # SQL Injection detection
│   └── reporter.py       # HTML report generator
│
├── main.py               # Entry point / CLI
├── requirements.txt      # Dependencies
└── README.md
```

---

## ⚙️ Installation
```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/web-vuln-scanner.git
cd web-vuln-scanner

# Create virtual environment
python -m venv venv
venv\Scripts\activate      # Windows
source venv/bin/activate   # macOS/Linux

# Install dependencies
pip install -r requirements.txt
```

---

## 💻 Usage
```bash
python main.py --target "http://zero.webappsecurity.com/login.html"
```

### Example Output
```
🔍 Starting scan on: http://zero.webappsecurity.com/login.html

→ Fetching target...
✓ Got response: HTTP 200

→ Checking security headers...
✓ 0 headers present, 6 missing

→ Testing for reflected XSS...
✓ XSS check done: 0 finding(s)

→ Testing for SQL Injection...
✓ SQLi check done: 0 finding(s)

📋 Scan Results:
╭──────────┬───────────────────────┬──────────────────────────────────────╮
│ Severity │ Type                  │ Detail                               │
├──────────┼───────────────────────┼──────────────────────────────────────┤
│ MEDIUM   │ Missing Security      │ Content-Security-Policy is missing   │
│          │ Header                │ Prevents XSS by controlling sources  │
╰──────────┴───────────────────────┴──────────────────────────────────────╯

📄 Report saved: report.html
```

---

## 📊 OWASP Coverage

| Check | OWASP Category |
|---|---|
| Missing Security Headers | A05 - Security Misconfiguration |
| Reflected XSS | A03 - Injection |
| SQL Injection | A03 - Injection |

---

## ⚠️ Disclaimer

This tool is intended for **educational purposes only**. Only scan websites you own or have explicit permission to test. Unauthorized scanning is illegal.

---

## 👤 Author

**Vedant Vyawhare**  
B.Tech CSE | MIT-WPU, Pune 