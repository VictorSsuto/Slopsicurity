"""HTTP security headers analysis."""
from .base import BaseScanner, Finding, ScanResult


# (header_name, check_id, label, max_score, recommendation, validator)
HEADER_CHECKS = [
    (
        "Strict-Transport-Security",
        "hdr_hsts",
        "HSTS (Strict-Transport-Security)",
        10,
        "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        lambda v: "max-age" in v.lower(),
    ),
    (
        "Content-Security-Policy",
        "hdr_csp",
        "Content-Security-Policy",
        15,
        (
            "Define a CSP header to prevent XSS. Start with: "
            "Content-Security-Policy: default-src 'self'"
        ),
        lambda v: len(v) > 5,
    ),
    (
        "X-Frame-Options",
        "hdr_xfo",
        "X-Frame-Options (Clickjacking Protection)",
        8,
        "Add header: X-Frame-Options: DENY  (or use CSP frame-ancestors directive).",
        lambda v: v.upper() in ("DENY", "SAMEORIGIN"),
    ),
    (
        "X-Content-Type-Options",
        "hdr_xcto",
        "X-Content-Type-Options (MIME Sniffing)",
        8,
        "Add header: X-Content-Type-Options: nosniff",
        lambda v: v.lower() == "nosniff",
    ),
    (
        "Referrer-Policy",
        "hdr_rp",
        "Referrer-Policy",
        5,
        "Add header: Referrer-Policy: strict-origin-when-cross-origin",
        lambda v: len(v) > 0,
    ),
    (
        "Permissions-Policy",
        "hdr_pp",
        "Permissions-Policy",
        5,
        (
            "Add header: Permissions-Policy: geolocation=(), microphone=(), camera=() "
            "to restrict browser feature access."
        ),
        lambda v: len(v) > 0,
    ),
    (
        "X-XSS-Protection",
        "hdr_xxp",
        "X-XSS-Protection (legacy)",
        3,
        "Add header: X-XSS-Protection: 1; mode=block (legacy browsers).",
        lambda v: v.startswith("1"),
    ),
]

# Headers that should NOT be present (information leakage)
LEAKY_HEADERS = [
    ("Server", "hdr_server_leak", "Server Header Not Leaking Version", 5,
     "Configure your server to omit or genericize the Server header."),
    ("X-Powered-By", "hdr_powered_leak", "X-Powered-By Header Absent", 5,
     "Remove the X-Powered-By header to avoid revealing your tech stack."),
    ("X-AspNet-Version", "hdr_aspnet_leak", "X-AspNet-Version Header Absent", 3,
     "Set <httpRuntime enableVersionHeader='false' /> in your web.config."),
]


class HeadersScanner(BaseScanner):
    name = "Security Headers"

    def run(self) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        try:
            resp = self.session.get(self.target, timeout=15, allow_redirects=True)
        except Exception as e:
            result.error = str(e)
            return result

        headers = {k.lower(): v for k, v in resp.headers.items()}

        for hdr_name, check_id, label, max_score, reco, validator in HEADER_CHECKS:
            value = headers.get(hdr_name.lower(), "")
            present = bool(value)
            valid = present and validator(value)
            result.findings.append(Finding(
                check_id=check_id,
                category="Security Headers",
                label=label,
                passed=valid,
                score=max_score if valid else 0,
                max_score=max_score,
                detail=f'Value: "{value}"' if present else "Header not present",
                recommendation=None if valid else reco,
            ))

        for hdr_name, check_id, label, max_score, reco in LEAKY_HEADERS:
            value = headers.get(hdr_name.lower(), "")
            # Pass = header absent or value doesn't reveal version info
            leaking = bool(value) and any(c.isdigit() for c in value)
            passed = not leaking
            result.findings.append(Finding(
                check_id=check_id,
                category="Information Leakage",
                label=label,
                passed=passed,
                score=max_score if passed else 0,
                max_score=max_score,
                detail=f'Header value: "{value}"' if value else "Header absent (good)",
                recommendation=None if passed else reco,
            ))

        return result
