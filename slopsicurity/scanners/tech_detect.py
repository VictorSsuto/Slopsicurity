"""Technology fingerprinting via headers, cookies, and HTML patterns."""
import re
from .base import BaseScanner, Finding, ScanResult

# Signatures: (name, pattern_type, pattern)
TECH_SIGNATURES = [
    # CMS
    ("WordPress",     "body",   r'wp-content|wp-includes|wordpress'),
    ("Joomla",        "body",   r'<div[^>]+id=["\']wrapper_r|joomla'),
    ("Drupal",        "header", r'X-Generator.*Drupal'),
    ("Drupal",        "body",   r'sites/default/files|drupal\.js'),
    ("Shopify",       "body",   r'cdn\.shopify\.com|Shopify\.theme'),
    ("Squarespace",   "body",   r'squarespace\.com|static\.squarespace'),
    ("Wix",           "body",   r'static\.wixstatic\.com|wix\.com'),
    # Frameworks
    ("Django",        "header", r'csrfmiddlewaretoken'),
    ("Django",        "cookie", r'csrftoken'),
    ("Laravel/PHP",   "cookie", r'laravel_session|XSRF-TOKEN'),
    ("ASP.NET",       "header", r'X-AspNet-Version|X-Powered-By.*ASP'),
    ("ASP.NET",       "cookie", r'ASP\.NET_SessionId'),
    ("Ruby on Rails", "cookie", r'_session_id'),
    ("Next.js",       "body",   r'__NEXT_DATA__|_next/static'),
    ("React",         "body",   r'__react|data-reactroot|react-dom'),
    ("Angular",       "body",   r'ng-version|angular\.min\.js'),
    ("Vue.js",        "body",   r'__vue__|vue\.min\.js'),
    # Servers
    ("nginx",         "header", r'Server.*nginx'),
    ("Apache",        "header", r'Server.*Apache'),
    ("Cloudflare",    "header", r'CF-RAY|Server.*cloudflare'),
    ("Varnish",       "header", r'X-Varnish|Via.*varnish'),
    # Analytics / tracking
    ("Google Analytics", "body", r'google-analytics\.com/analytics|gtag\('),
    ("Hotjar",           "body", r'hotjar\.com|hjid'),
]

# Known outdated/risky tech worth flagging with penalty
RISKY_TECH = {
    "WordPress": (
        "WordPress sites are frequent targets. Keep WP core, themes, and plugins updated. "
        "Use a WAF (e.g., Cloudflare) and disable XML-RPC if unused."
    ),
    "Joomla": "Keep Joomla and all extensions up to date. Disable unused plugins.",
    "Drupal": "Apply Drupal security updates promptly ('Drupalgeddon' class vulns are common).",
    "ASP.NET": (
        "Suppress version headers: remove X-AspNet-Version and X-Powered-By in web.config."
    ),
}

# Human-readable categories for informational findings
TECH_CATEGORY = {
    "nginx":           "Web Server",
    "Apache":          "Web Server",
    "Varnish":         "Cache/Proxy",
    "Cloudflare":      "CDN/WAF",
    "Django":          "Framework",
    "Laravel/PHP":     "Framework",
    "Ruby on Rails":   "Framework",
    "Next.js":         "Framework",
    "React":           "Framework",
    "Angular":         "Framework",
    "Vue.js":          "Framework",
    "Shopify":         "Platform",
    "Squarespace":     "Platform",
    "Wix":             "Platform",
    "Google Analytics":"Analytics",
    "Hotjar":          "Analytics",
}

def _tech_check_id(name: str) -> str:
    return "tech_" + re.sub(r'[^a-z0-9]', '_', name.lower()).strip('_')


class TechScanner(BaseScanner):
    name = "Technology Detection"

    def run(self) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        try:
            resp = self.session.get(self.target, timeout=15, allow_redirects=True)
        except Exception as e:
            result.error = str(e)
            return result

        headers_str = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        cookies_str = " ".join(resp.cookies.keys())
        body = resp.text[:50_000]

        detected = set()
        for tech, pattern_type, pattern in TECH_SIGNATURES:
            if tech in detected:
                continue
            target_text = {
                "header": headers_str,
                "cookie": cookies_str,
                "body": body,
            }.get(pattern_type, "")
            if re.search(pattern, target_text, re.IGNORECASE):
                detected.add(tech)

        if not detected:
            result.findings.append(Finding(
                check_id="tech_fingerprint_low",
                category="Technology Detection",
                label="Low Technology Fingerprint",
                passed=True,
                score=5,
                max_score=5,
                detail="No obvious technology signatures detected — good fingerprint hygiene.",
            ))
            return result

        risky = [t for t in detected if t in RISKY_TECH]
        safe  = [t for t in detected if t not in RISKY_TECH]

        # Risky tech → individual failing findings (scored)
        for tech in sorted(risky):
            result.findings.append(Finding(
                check_id=_tech_check_id(tech),
                category="Technology Detection",
                label=f"Risky Tech: {tech}",
                passed=False,
                score=0,
                max_score=5,
                detail=f"{tech} fingerprint detected",
                recommendation=RISKY_TECH[tech],
            ))

        # Safe tech → individual informational findings (unscored)
        # Emitting one per tech lets downstream code detect server type by check_id.
        for tech in sorted(safe):
            category = TECH_CATEGORY.get(tech, "Technology")
            result.findings.append(Finding(
                check_id=_tech_check_id(tech),
                category="Technology Detection",
                label=f"{tech} Detected",
                passed=True,
                score=0,
                max_score=0,
                detail=f"{category}: {tech}",
            ))

        return result
