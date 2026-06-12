# 🛡 Slopsicurity

> Non-invasive website security scanner. **LOOK, don't TOUCH.**

Slopsicurity performs passive, read-only security checks on any public website and produces a scored report with actionable recommendations.

## What it checks

| Category | Checks |
|---|---|
| **SSL/TLS** | HTTPS enforced, cert validity, expiry warning, TLS version |
| **Security Headers** | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, XSS-Protection |
| **Information Leakage** | Server / X-Powered-By header exposure |
| **Technology Detection** | CMS, frameworks, CDNs — flags risky stacks |
| **File Exposure** | `.git/`, `.env`, backups, phpinfo, SQL dumps, etc. |
| **DNS & Domain** | SPF, DMARC, CAA records |

## Installation

```bash
git clone https://github.com/yourorg/slopsicurity
cd slopsicurity
pip install -r requirements.txt
```

## Usage

```bash
# Terminal scoreboard (default)
python main.py https://example.com

# JSON output
python main.py https://example.com --json

# Save JSON report to file
python main.py https://example.com --output report.json

# Verbose (show per-scanner timing)
python main.py https://example.com -v
```

## Scoring

| Grade | Score | Meaning |
|---|---|---|
| A+ | ≥ 95% | Excellent |
| A  | ≥ 80% | Strong |
| B  | ≥ 65% | Good |
| C  | ≥ 50% | Fair |
| D  | ≥ 30% | Poor |
| F  | < 30% | Critical |

Exit code is `0` for A/A+ grades, `1` otherwise — useful in CI pipelines.

## Legal

This tool performs **non-invasive, passive checks only**. It reads publicly exposed data — no exploitation, no brute force, no payloads. Use only on sites you own or have explicit permission to test.

See `TERMS.md` for full terms of use.
