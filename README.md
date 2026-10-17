# SQL_Injector
from pathlib import Path

content = r"""# SQL Injection Scanner

A Python 3, object-oriented web scanner for identifying common SQL injection indicators in an isolated lab environment. The default target is the DVWA instance at `http://192.168.163.128/`.

## Contents

- [Overview](#overview)
- [Features](#features)
- [Project Structure](#project-structure)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configure DVWA](#configure-dvwa)
- [Run the Scanner](#run-the-scanner)
- [Command-Line Options](#command-line-options)
- [How It Works](#how-it-works)
- [Detection Methods](#detection-methods)
- [Output and Reports](#output-and-reports)
- [Troubleshooting](#troubleshooting)
- [Limitations](#limitations)
- [Remediation Guidance](#remediation-guidance)

## Overview

The scanner sends a bounded set of test inputs to discovered GET and POST parameters, then checks responses for signs that user-controlled input may affect SQL queries. It includes same-host link discovery, basic concurrency, a shared request-rate limiter, logging, and JSON reporting.

It is a detection aid, not proof that a vulnerability exists or that an application is secure. Findings require manual validation.

## Features

- Object-oriented Python implementation.
- Same-host HTML link and form discovery.
- GET query-string and basic HTML form parameter testing.
- SQL error-signature detection.
- Boolean true/false response comparison.
- Short, bounded time-delay indicator checks.
- Thread pool with a configurable worker count.
- Shared request-start rate limiter.
- Request timeout and exception handling.
- Timestamped terminal/file logging.
- JSON report with evidence, severity, confidence, and test metadata.

The scanner does not extract database contents, alter database records, or run stacked SQL statements.

## Project Structure

```text
sql_injection_scanner/
├── sql_scanner.py       # Scanner implementation
├── requirements.txt     # Python dependencies
├── sql_scanner.log      # Created at runtime
└── sql_report.json      # Created at runtime
```

## Requirements

- Python 3.9 or newer recommended.
- Network access from the scanning machine to the lab target.
- DVWA or another deliberately vulnerable test application.
- Dependencies listed in `requirements.txt`:
  - `requests`
  - `beautifulsoup4`

## Installation

On Kali Linux or another Linux distribution:

```bash
mkdir -p sql_injection_scanner
cd sql_injection_scanner

# Save sql_scanner.py and requirements.txt in this directory.
python3 -m venv venv
source venv/bin/activate

python -m pip install --upgrade pip
pip install -r requirements.txt
```

If you use a distribution-managed Python that blocks global package installation, use the virtual environment commands above instead of forcing a system-wide install.

## Configure DVWA

1. Confirm that the target web server is reachable:

   ```bash
   curl -i http://192.168.163.128/dvwa/login.php
   ```

2. Open this URL in a browser:

   `http://192.168.163.128/dvwa/login.php`

3. On a default DVWA installation, the web credentials are commonly:

   ```text
   Username: admin
   Password: password
   ```

   These may have been changed by the VM image or administrator.

4. Log in, open **DVWA Security**, choose **Low**, and submit the setting.
5. Open the SQL Injection module and confirm that it loads.

**Authentication limitation:** the scanner as currently written does not log in to DVWA, preserve a browser-authenticated session, or handle DVWA CSRF tokens. A command-line scan of a protected page may only receive a login page or redirect, so it may discover no injection parameters. Logging in with a browser does not automatically authenticate the scanner's separate HTTP session.

## Run the Scanner

Default target (`http://192.168.163.128/`):

```bash
python3 sql_scanner.py
```

Target the DVWA installation explicitly:

```bash
python3 sql_scanner.py \
  --target http://192.168.163.128/dvwa/ \
  --max-pages 30 \
  --workers 2 \
  --rate 1 \
  --timeout 6 \
  --delay 3
```

Use a trailing slash on the application base URL where appropriate. The target option accepts an HTTP or HTTPS URL, including a path.

### Suggested initial settings

Start with a small worker count and a low request rate. Increase the page limit only if the application has more pages to inspect. Higher concurrency does not improve detection logic and may make timing-based results less reliable.

## Command-Line Options

| Option | Default | Description |
|---|---:|---|
| `--target` | `http://192.168.163.128/` | Target HTTP/HTTPS URL |
| `--max-pages` | `30` | Maximum number of pages accepted by the crawler |
| `--workers` | `2` | Concurrent parameter-test workers; implementation caps this at 4 |
| `--rate` | `1.0` | Aggregate request-start limit in requests per second |
| `--timeout` | `6` | HTTP timeout in seconds; implementation bounds it to 2–15 seconds |
| `--delay` | `3` | Delay value used by time-based indicator probes; allowed values are 1, 2, or 3 seconds |

Example with a smaller crawl:

```bash
python3 sql_scanner.py \
  --target http://192.168.163.128/dvwa/ \
  --max-pages 10 \
  --workers 1 \
  --rate 0.5
```

## How It Works

1. **Initialize:** parse the target and scanner options, set up logging, and create the shared rate limiter.
2. **Request the starting page:** make an HTTP GET request and check whether the response is HTML.
3. **Discover inputs:** parse same-host links, query-string parameters, and basic HTML forms.
4. **Build parameter tests:** create test tasks for discovered GET and POST parameters and remove duplicate tasks.
5. **Establish a baseline:** submit a neutral marker value to the parameter and retain the response.
6. **Error-based checks:** send a small set of quote/syntax probes and inspect response bodies for known database error signatures.
7. **Boolean differential checks:** compare responses to paired true-like and false-like expressions. A difference is only an indicator because dynamic page content can also change.
8. **Timing checks:** compare a small number of baseline requests with short database-delay probes. Network jitter can cause false positives.
9. **Record evidence:** store a finding when the implemented detection rule is met.
10. **Write reports:** save a JSON report and log activity to `sql_scanner.log`, then print a terminal summary.

## Detection Methods

### Error-based indicators

The scanner looks for common error strings associated with MySQL/MariaDB, PostgreSQL, SQLite, Microsoft SQL Server, Oracle, and generic SQL errors. A matching string suggests that database error details may be exposed, but does not alone prove that the tested parameter is exploitable.

### Boolean-based indicators

The scanner submits paired expressions intended to produce different logical outcomes and compares normalized response text, status codes, and response lengths. The current implementation only reports a finding when several comparison conditions are met. Applications that render dynamic tokens, timestamps, or personalized content can still cause false positives or false negatives.

### Time-based indicators

The scanner sends a small set of short delay probes and compares elapsed time with baseline requests. A slow response can be caused by server load, network delay, or application behavior rather than SQL injection. Treat timing results as low-certainty evidence until repeated and manually validated.

## Output and Reports

### Terminal summary

The program prints:

- Target URL.
- Number of pages crawled.
- Number of parameter tests created.
- Number of findings.
- For each finding: severity, category, URL, HTTP method, parameter, confidence, evidence, and the probe used.

Example format (illustrative only; actual results depend on the target):

```text
========== SCAN SUMMARY ==========
Target: http://192.168.163.128/dvwa/
Pages crawled: 8
Parameter tests: 5
Findings: 1

[1] Medium — SQL error disclosure
URL: http://192.168.163.128/dvwa/vulnerabilities/sqli/
Method: GET
Parameter: id
Confidence: high
Evidence: Database error signature: ...
Payload: '
```

This is an example of the output format, not a claim that the target has been tested or is vulnerable.

### `sql_report.json`

The JSON file contains:

- `target`: target URL.
- `generated_at`: UTC report-generation timestamp.
- `pages_crawled`: number of pages accepted by the crawler.
- `parameter_tests`: number of unique parameter-test tasks.
- `finding_count`: total recorded findings.
- `findings`: list of findings, each including URL, method, parameter, category, severity, evidence, payload, and confidence.

View the summary with:

```bash
python3 - <<'PY'
import json

with open("sql_report.json", encoding="utf-8") as file:
    report = json.load(file)

print("Target:", report["target"])
print("Pages crawled:", report["pages_crawled"])
print("Parameter tests:", report["parameter_tests"])
print("Findings:", report["finding_count"])

for item in report["findings"]:
    print(
        item["severity"],
        item["category"],
        item["method"],
        item["url"],
        "parameter=" + item["parameter"],
        "confidence=" + item["confidence"],
    )
PY
```

### `sql_scanner.log`

The log records crawl activity, findings, request failures, and report creation. Inspect relevant entries with:

```bash
grep -Ei 'Crawled|FINDING|failed|error|report' sql_scanner.log
```

## Troubleshooting

### The scanner reports zero pages

Check connectivity and the URL:

```bash
curl -i http://192.168.163.128/
curl -i http://192.168.163.128/dvwa/login.php
```

Check the VM network configuration and verify that the web server is running.

### Pages are crawled, but parameter tests are zero

The starting page may not contain links or forms with testable parameters, or the scanner may be seeing a login page. The current crawler does not automatically authenticate. Confirm that the SQL Injection module is accessible and that the target URL is correct.

### Parameter tests run, but no findings appear

A zero-finding result is inconclusive. The application may not be vulnerable, may be using a different database/error format, may require authentication or CSRF handling, or may return responses that do not match the scanner's heuristics. Verify the DVWA page manually at Low security and review the HTTP response and log.

### HTTP 302 or a login form appears

This commonly indicates a redirect or unauthenticated session. The scanner does not currently implement a DVWA login flow, cookie import, or CSRF-token management.

### Time-based results are inconsistent

Reduce concurrency and request rate, repeat the test, and compare with fresh baseline requests. Do not classify a single slow response as definitive evidence.

## Limitations

This is a small educational scanner, not a full-featured DAST platform.

- No automatic DVWA authentication, CSRF token handling, or session-cookie import.
- Basic synchronous page discovery rather than a scalable crawl queue.
- Limited HTML form support; JavaScript-generated forms and API requests are not discovered.
- Duplicate query parameter names and complex input controls are not comprehensively handled.
- Error signatures are incomplete and database-dependent.
- Boolean comparison can be affected by dynamic page content.
- Timing checks can produce false positives and false negatives.
- No authenticated API schema discovery, out-of-band testing, database enumeration, or data extraction.
- Severity and confidence are heuristic labels, not a formal CVSS assessment.

## Remediation Guidance

If a finding is validated:

1. Use parameterized queries or prepared statements instead of concatenating user input into SQL.
2. Apply allow-list validation for values that must follow a specific format, such as numeric IDs.
3. Use a database account with only the permissions the application needs.
4. Disable detailed SQL error messages in production and log diagnostic details server-side.
5. Add regression tests for the affected parameter and query path.
6. Retest the same request after the fix and confirm that the behavior no longer depends on injected SQL syntax.

## License and Scope

This project is intended for controlled testing against DVWA, local applications, and other explicitly designated lab targets. Keep scans within the configured target host; the crawler is designed to reject links outside the target origin.
"""

path = Path("/mnt/data/README.md")
path.write_text(content, encoding="utf-8")
print(f"Created: {path}")
