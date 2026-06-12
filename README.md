# 🛡 Slopsicurity

> Non-invasive website security scanner. **LOOK, don't TOUCH.**

Slopsicurity performs passive, read-only security checks on any public website and produces a scored report with actionable, personalized recommendations. It behaves as an auditor — not an attacker.

---

## Table of Contents

- [Quick Start](#quick-start)
- [Usage](#usage)
- [Scoring System](#scoring-system)
- [Project Structure](#project-structure)
- [Module Reference](#module-reference)
  - [main.py](#mainpy)
  - [scanners/base.py](#scannerbasepy)
  - [scanners/ssl_check.py](#scannerssl_checkpy)
  - [scanners/headers.py](#scannersheaderspy)
  - [scanners/tech_detect.py](#scannerstech_detectpy)
  - [scanners/file_exposure.py](#scannersfile_exposurepy)
  - [scanners/dns_info.py](#scannersdns_infopy)
  - [scoring/engine.py](#scoringenginepy)
  - [reporting/terminal.py](#reportingterminalpy)
  - [reporting/json_out.py](#reportingjson_outpy)
- [Legal](#legal)

---

## Quick Start

```bash
git clone https://github.com/VictorSsuto/Slopsicurity
cd Slopsicurity
pip3 install -r requirements.txt
python main.py https://yoursite.com
```

---

## Usage

```bash
# Terminal scoreboard (default)
python main.py https://example.com

# JSON output to stdout
python main.py https://example.com --json

# Save JSON report to file
python main.py https://example.com --output report.json

# Verbose mode — shows per-scanner timing
python main.py https://example.com --verbose
```

Exit code is `0` for A/A+ grades, `1` for anything lower — useful in CI pipelines.

---

## Scoring System

Every check carries a point value. Points are awarded when a check passes and withheld when it fails. The total score is expressed as a percentage, which maps to a letter grade.

| Grade | Threshold | Meaning |
|-------|-----------|---------|
| A+    | ≥ 95%     | Excellent — industry-leading security posture |
| A     | ≥ 80%     | Strong — most best practices followed |
| B     | ≥ 65%     | Good — a few gaps worth addressing |
| C     | ≥ 50%     | Fair — notable issues present |
| D     | ≥ 30%     | Poor — significant vulnerabilities exposed |
| F     | < 30%     | Critical — serious security failures |

### Check Point Values

| Category | Check | Points |
|----------|-------|--------|
| SSL/TLS | HTTPS Enforced | 15 |
| SSL/TLS | Certificate Valid & Not Expired | 10 |
| SSL/TLS | Certificate Expiry > 30 Days | 5 |
| SSL/TLS | Modern TLS Version (1.2+) | 10 |
| Security Headers | Content-Security-Policy | 15 |
| Security Headers | HSTS | 10 |
| Security Headers | X-Frame-Options | 8 |
| Security Headers | X-Content-Type-Options | 8 |
| Security Headers | Referrer-Policy | 5 |
| Security Headers | Permissions-Policy | 5 |
| Security Headers | X-XSS-Protection | 3 |
| Information Leakage | Server Header Not Leaking Version | 5 |
| Information Leakage | X-Powered-By Header Absent | 5 |
| Information Leakage | X-AspNet-Version Header Absent | 3 |
| File Exposure | .git/ Exposed | 15 |
| File Exposure | .env Exposed | 15 |
| File Exposure | Database Dump Exposed | 15 |
| File Exposure | Config Backup Exposed | 12 |
| File Exposure | phpinfo() Exposed | 10 |
| File Exposure | Apache server-status / ELMAH / trace.axd | 8 each |
| DNS | Domain Resolves | 5 |
| DNS / Email | SPF Record Present | 8 |
| DNS / Email | DMARC Record Present | 8 |
| DNS | CAA Record Present | 5 |

---

## Project Structure

```
Slopsicurity/
├── main.py                          # CLI entrypoint
├── requirements.txt
├── .gitignore
├── README.md
└── slopsicurity/
    ├── __init__.py
    ├── scanners/
    │   ├── __init__.py              # Exports ALL_SCANNERS list
    │   ├── base.py                  # Shared data classes + BaseScanner
    │   ├── ssl_check.py             # SSL/TLS checks
    │   ├── headers.py               # HTTP security header checks
    │   ├── tech_detect.py           # Technology fingerprinting
    │   ├── file_exposure.py         # Sensitive file/path checks
    │   └── dns_info.py              # DNS, SPF, DMARC, CAA checks
    ├── scoring/
    │   ├── __init__.py
    │   └── engine.py                # Scoring logic + grade assignment
    └── reporting/
        ├── __init__.py
        ├── terminal.py              # Colored terminal output
        └── json_out.py              # JSON serializer
```

---

## Module Reference

---

### `main.py`

The CLI entrypoint. Wires together the scanner, scorer, and reporter.

---

#### `normalize_url(raw: str) -> str`

Cleans and normalizes a raw URL string before scanning.

- If the input has no scheme (`http://` or `https://`), prepends `https://` automatically.
- Strips trailing slashes from the path to avoid duplicate checks.
- Returns a fully-formed URL string (e.g. `https://example.com`).

**Example:**
```
"example.com"        → "https://example.com"
"http://example.com/" → "http://example.com"
```

---

#### `build_session(timeout: int = 15) -> requests.Session`

Creates and configures a shared `requests.Session` used by all scanner modules.

- Sets a descriptive `User-Agent` header identifying the tool as Slopsicurity so server logs can identify the scanner.
- The session is reused across all scanner modules to benefit from connection pooling and consistent headers.

---

#### `run_scan(url: str, verbose: bool = False) -> ScoreReport`

Orchestrates the full scan pipeline.

- Calls `build_session()` to create the HTTP session.
- Iterates through every scanner class in `ALL_SCANNERS`, instantiating each with the target URL and shared session.
- Calls `.run()` on each scanner and collects the resulting `ScanResult` objects.
- If `verbose=True`, prints each scanner's name and how long it took to run.
- Passes all results to `score_results()` and returns the final `ScoreReport`.

---

#### `main()`

The CLI entry point called when the script is run directly.

- Uses `argparse` to parse the command-line arguments: `url`, `--json`, `--output`, `--verbose`.
- Normalizes the URL and runs the scan.
- If `--output` or `--json` is provided, serializes the report to JSON (either saving to a file or printing to stdout).
- Otherwise, calls `print_report()` to display the colored terminal scoreboard.
- Exits with code `0` if the grade is A or A+, `1` for any lower grade.

---

### `scanners/base.py`

Defines the shared data structures used by every scanner module.

---

#### `class Finding` (dataclass)

Represents a single security check result. Every check in the system produces one `Finding`.

| Field | Type | Description |
|-------|------|-------------|
| `check_id` | `str` | Unique identifier for the check (e.g. `"ssl_https"`) |
| `category` | `str` | Display category (e.g. `"SSL/TLS"`) |
| `label` | `str` | Human-readable check name shown in the report |
| `passed` | `bool` | Whether the check passed |
| `score` | `int` | Points actually earned (0 if failed) |
| `max_score` | `int` | Maximum points this check is worth |
| `detail` | `str` | What was observed (e.g. the actual header value found) |
| `recommendation` | `str \| None` | Actionable fix shown when the check fails; `None` if passed |

Findings with `max_score=0` are informational only — they appear in the report but don't affect the score.

---

#### `class ScanResult` (dataclass)

The output of one complete scanner module run.

| Field | Type | Description |
|-------|------|-------------|
| `scanner_name` | `str` | Display name of the scanner |
| `findings` | `list[Finding]` | All findings produced by this scanner |
| `error` | `str \| None` | Error message if the scanner failed to run |

**Properties:**

- `score` — sum of `f.score` across all findings (points earned by this scanner).
- `max_score` — sum of `f.max_score` across all findings (max points available from this scanner).

---

#### `class BaseScanner`

Abstract base class that all scanner modules extend.

**`__init__(self, target: str, session)`**

Stores the target URL and shared `requests.Session` as instance attributes. Every subclass calls this via inheritance.

**`run(self) -> ScanResult`**

Abstract method — must be implemented by every subclass. Contains the scanner's logic and returns a populated `ScanResult`.

---

### `scanners/ssl_check.py`

Checks SSL/TLS configuration by opening a real TLS connection to the target.

---

#### `class SSLScanner(BaseScanner)`

**`run(self) -> ScanResult`**

Runs four checks in sequence:

1. **HTTPS Enforced** (15 pts) — Checks whether the URL scheme is `https`. If it's plain `http`, the remaining checks are skipped and 0 points are awarded.

2. **Certificate Valid & Not Expired** (10 pts) — Parses the `notAfter` field from the certificate returned by `_fetch_cert()`. Calculates days remaining and awards points only if the cert has not yet expired.

3. **Certificate Expiry > 30 Days** (5 pts) — An early-warning check. Even if the certificate is technically valid, this check fails if fewer than 30 days remain before expiry, prompting renewal before downtime occurs.

4. **Modern TLS Version** (10 pts) — Checks the negotiated TLS protocol version. Passes only for `TLSv1.2` or `TLSv1.3`. Older versions (TLS 1.0, TLS 1.1) are deprecated and insecure.

---

#### `_fetch_cert(self, hostname: str, port: int) -> tuple | None`

Opens a real TLS socket connection to `hostname:port` using Python's `ssl` module with the system's default certificate verification context.

- Returns a `(cert_dict, protocol_str)` tuple on success, where `cert_dict` is the parsed certificate from `getpeercert()` and `protocol_str` is the negotiated TLS version (e.g. `"TLSv1.3"`).
- Returns `None` if the connection fails for any reason (invalid cert, timeout, unreachable host).
- Uses a 10-second connection timeout to avoid hanging.

---

### `scanners/headers.py`

Analyzes HTTP response headers for security misconfigurations and information leakage.

---

#### Module-level constants

**`HEADER_CHECKS`** — A list of tuples defining each security header to look for. Each tuple contains:
- The header name to look up
- A unique `check_id`
- A human-readable label
- The maximum point value
- A recommendation string shown if the header is missing or misconfigured
- A validator function (lambda) that takes the header's value and returns `True` if it is correctly configured

The headers checked and their validators are:

| Header | What the validator checks |
|--------|--------------------------|
| `Strict-Transport-Security` | Value must contain `max-age` |
| `Content-Security-Policy` | Value must be non-empty (>5 chars) |
| `X-Frame-Options` | Value must be `DENY` or `SAMEORIGIN` |
| `X-Content-Type-Options` | Value must be exactly `nosniff` |
| `Referrer-Policy` | Any non-empty value |
| `Permissions-Policy` | Any non-empty value |
| `X-XSS-Protection` | Value must start with `1` |

**`LEAKY_HEADERS`** — A list of tuples defining headers that should **not** reveal version information. Each tuple contains the header name, check ID, label, point value, and recommendation. These checks pass when the header is absent or contains no digits (version numbers).

| Header | Why it's risky |
|--------|----------------|
| `Server` | Reveals server software and version (e.g. `Apache/2.4.51`) |
| `X-Powered-By` | Reveals backend language/framework (e.g. `PHP/8.1`) |
| `X-AspNet-Version` | Reveals exact ASP.NET version |

---

#### `class HeadersScanner(BaseScanner)`

**`run(self) -> ScanResult`**

Makes a single GET request to the target URL (following redirects) and inspects the response headers.

- Normalizes all header names to lowercase for case-insensitive comparison.
- Iterates through `HEADER_CHECKS`: for each, looks up the header value, runs the validator, and creates a `Finding` with the appropriate score.
- Iterates through `LEAKY_HEADERS`: passes if the header is absent or its value contains no digit characters (i.e. no version number is being leaked).
- If the HTTP request itself fails, sets `result.error` and returns early.

---

### `scanners/tech_detect.py`

Fingerprints the technology stack by matching regex patterns against response headers, cookies, and HTML body.

---

#### Module-level constants

**`TECH_SIGNATURES`** — A list of `(name, pattern_type, regex_pattern)` tuples. The scanner tests each pattern against the appropriate part of the HTTP response:

- `"header"` — matched against all response headers concatenated as a string
- `"cookie"` — matched against cookie names
- `"body"` — matched against the first 50 KB of the HTML body

Technologies detected include: WordPress, Joomla, Drupal, Shopify, Squarespace, Wix, Django, Laravel/PHP, ASP.NET, Ruby on Rails, Next.js, React, Angular, Vue.js, nginx, Apache, Cloudflare, Varnish, Google Analytics, and Hotjar.

**`RISKY_TECH`** — A dictionary mapping technology names to specific security recommendation strings. Technologies listed here (WordPress, Joomla, Drupal, ASP.NET) are flagged as `passed=False` findings, costing up to 5 points each, because they carry known security risks that require active maintenance.

---

#### `class TechScanner(BaseScanner)`

**`run(self) -> ScanResult`**

Makes a GET request and tests all signatures against the response.

- Caps HTML body inspection at 50,000 characters to avoid slow parsing of very large pages.
- Tracks detected technologies in a set to avoid duplicate detections.
- Splits detections into two groups:
  - **Risky** (in `RISKY_TECH`): generates a failing `Finding` per technology with a specific recommendation.
  - **Safe/informational** (not in `RISKY_TECH`): generates a single informational `Finding` (score 0, max 0) listing all detected tech.
- If nothing is detected at all, awards 5 bonus points for **Low Technology Fingerprint** — a sign the site avoids revealing its stack.

---

### `scanners/file_exposure.py`

Checks whether sensitive files and paths are publicly accessible via HTTP.

---

#### Module-level constants

**`SENSITIVE_PATHS`** — A list of `(path, label, penalty_points, description)` tuples. Each path is checked with a GET request. A response of HTTP 200 with non-empty content is considered "exposed."

Paths checked include:

| Path | Risk | Points |
|------|------|--------|
| `/.git/HEAD`, `/.git/config` | Full source code leak | 15 each |
| `/.env`, `/.env.local`, `/.env.production` | Credentials/secrets exposure | 15 each |
| `/database.sql`, `/db.sql` | Database dump exposure | 15 each |
| `/wp-config.php.bak`, `/config.php.bak`, `/backup.zip`, `/backup.tar.gz` | Config/backup exposure | 12 each |
| `/phpinfo.php` | PHP environment info leak | 10 |
| `/server-status`, `/elmah.axd`, `/trace.axd`, `/.htaccess` | Server config info leak | 8 each |
| `/crossdomain.xml`, `/clientaccesspolicy.xml` | Cross-domain policy exposure | 3 each |
| `/robots.txt`, `/sitemap.xml` | Informational only | 0 |

---

#### `class FileExposureScanner(BaseScanner)`

**`run(self) -> ScanResult`**

Iterates through every path in `SENSITIVE_PATHS` and makes a GET request with `allow_redirects=False` (to avoid false negatives from redirect chains).

- A file is considered **exposed** only if the status code is exactly `200` AND the response body is non-empty.
- Paths with `penalty=0` (robots.txt, sitemap.xml) are informational: they generate a `Finding` only if the file is present, and don't affect the score.
- For all other paths: if not exposed, the full penalty points are awarded (the site did the right thing); if exposed, 0 points are awarded and a specific recommendation is generated.
- If no findings were generated at all (e.g. all requests failed due to network issues), appends a single passing `Finding` worth 10 points for having no exposed sensitive files.

---

### `scanners/dns_info.py`

Checks DNS configuration for security-related records.

---

#### `class DNSScanner(BaseScanner)`

**`run(self) -> ScanResult`**

Runs four DNS-level checks:

1. **Domain Resolves** (5 pts) — Uses `socket.gethostbyname()` to verify the hostname has a valid A record. If this fails, the scanner stops early since no other DNS checks make sense.

2. **SPF Record** (8 pts) — Calls `_txt_contains()` to look for a TXT record on the apex domain starting with `v=spf1`. SPF (Sender Policy Framework) prevents other servers from sending email on behalf of your domain.

3. **DMARC Record** (8 pts) — Calls `_txt_contains()` to look for a TXT record at `_dmarc.<apex>` starting with `v=DMARC1`. DMARC tells receiving mail servers what to do when SPF/DKIM checks fail, protecting against phishing using your domain.

4. **CAA Record** (5 pts) — Calls `_caa_record()` to check for a CAA (Certification Authority Authorization) DNS record. CAA records restrict which Certificate Authorities are allowed to issue TLS certificates for the domain, preventing unauthorized cert issuance.

Strips leading `www.` from the hostname when looking up email security records (SPF, DMARC) since these are set on the apex domain.

---

#### `_txt_contains(self, name: str, prefix: str) -> str | None`

Queries DNS for TXT records at the given `name` and returns the first record whose decoded text starts with `prefix`.

- Uses `dnspython`'s `dns.resolver.resolve()` with an 8-second lifetime.
- Decodes each record's byte strings and checks for the given prefix.
- Returns the full TXT record string if found, `None` otherwise.
- Silently catches all exceptions (NXDOMAIN, timeout, etc.) and returns `None`.

---

#### `_caa_record(self, name: str) -> str | None`

Queries DNS for CAA records at the given `name`.

- Returns a semicolon-joined string of all CAA records if any exist.
- Returns `None` if no CAA records are found or on any DNS error.

---

### `scoring/engine.py`

Aggregates scanner results into a total score and letter grade.

---

#### `class Grade(str, Enum)`

An enumeration of the six possible letter grades: `A+`, `A`, `B`, `C`, `D`, `F`.

**`description` (property)** — Returns a human-readable description of what the grade means (e.g. `"Strong — most best practices followed"` for A).

**`color` (property)** — Returns an ANSI escape code for the terminal color associated with the grade (green for A/A+, yellow for B/C, red for D/F).

---

#### `class ScoreReport` (dataclass)

The final output object of a complete scan. Passed to the reporting modules for display.

| Field | Type | Description |
|-------|------|-------------|
| `url` | `str` | The scanned URL |
| `total_score` | `int` | Total points earned across all scanners |
| `max_score` | `int` | Total points available across all scanners |
| `percentage` | `float` | `total_score / max_score * 100`, rounded to 1 decimal |
| `grade` | `Grade` | Letter grade assigned by `_assign_grade()` |
| `scan_results` | `list[ScanResult]` | The raw results from each scanner |

**Properties:**

- `all_findings` — Flattens all `findings` lists from all `ScanResult` objects into a single list.
- `failures` — Filters `all_findings` to only those where `passed=False` and `max_score > 0` (i.e. real failures, not informational findings).
- `passes` — Filters `all_findings` to only those where `passed=True` and `max_score > 0`.

---

#### `_assign_grade(pct: float) -> Grade`

Internal function that maps a percentage score to a letter grade using fixed thresholds. Not called directly — used inside `score_results()`.

---

#### `score_results(url: str, scan_results: list[ScanResult]) -> ScoreReport`

The main public function of the scoring module. Called by `run_scan()` in `main.py`.

- Sums `score` and `max_score` across all `ScanResult` objects.
- Calculates the percentage and calls `_assign_grade()` to get the letter grade.
- Returns a fully populated `ScoreReport`.

---

### `reporting/terminal.py`

Renders the scored report as a formatted, colored terminal output.

---

#### `_bar(score: int, max_score: int, width: int = 20) -> str`

Generates a Unicode progress bar string representing how many points were earned out of the maximum.

- Filled portion uses `█` characters, empty portion uses `░`.
- Width defaults to 20 characters but can be customized (the main report uses 50).
- Returns a blank string of the given width if `max_score` is 0.

---

#### `_check_icon(passed: bool) -> str`

Returns a colored terminal string for a pass/fail icon.

- `✔` in green for passed checks.
- `✘` in red for failed checks.

---

#### `print_report(report: ScoreReport) -> None`

Prints the full terminal scoreboard to stdout. The output has four sections:

1. **Header** — Shows the target URL, total score, percentage, grade, and a full-width progress bar.
2. **Per-scanner findings** — Groups all findings by their scanner. Each finding shows the pass/fail icon, label, points earned, and the detail string. Findings with `max_score=0` are shown as dimmed informational lines.
3. **Recommendations** — If there are any failing checks, lists them in order of highest impact (most points lost first), with the specific fix recommendation for each.
4. **Summary footer** — Shows total count of passed vs. failed checks.

---

### `reporting/json_out.py`

Serializes a `ScoreReport` to a JSON string for programmatic use or file output.

---

#### `report_to_json(report: ScoreReport, indent: int = 2) -> str`

Converts the full `ScoreReport` into a structured JSON string.

The output JSON has this shape:

```json
{
  "url": "https://example.com",
  "score": {
    "total": 72,
    "max": 100,
    "percentage": 72.0,
    "grade": "B",
    "grade_description": "Good — a few gaps worth addressing"
  },
  "scanners": [
    {
      "name": "SSL/TLS",
      "score": 40,
      "max_score": 40,
      "error": null,
      "findings": [
        {
          "check_id": "ssl_https",
          "category": "SSL/TLS",
          "label": "HTTPS Enforced",
          "passed": true,
          "score": 15,
          "max_score": 15,
          "detail": "Site uses HTTPS",
          "recommendation": null
        }
      ]
    }
  ],
  "recommendations": [
    {
      "check_id": "hdr_csp",
      "label": "Content-Security-Policy",
      "impact_points": 15,
      "recommendation": "Define a CSP header to prevent XSS..."
    }
  ]
}
```

- `scanners` contains one entry per scanner module, preserving all raw findings.
- `recommendations` contains only the failed checks, sorted by `impact_points` descending (highest-value fixes first).

---

## Legal

This tool performs **non-invasive, passive checks only**. It reads publicly exposed data and makes no attempt to bypass authentication, inject payloads, or exploit vulnerabilities.

**Allowed:** Reading HTTP responses, inspecting headers, querying public DNS records, checking whether files return HTTP 200.

**Not allowed:** Brute force, SQL injection, sending malicious payloads, accessing private or authenticated resources.

Use only on sites you own or have explicit written permission to test.
