"""Check for publicly exposed sensitive files and directories."""
from urllib.parse import urljoin
from .base import BaseScanner, Finding, ScanResult

# (path, label, severity_score_penalty, description)
SENSITIVE_PATHS = [
    ("/.git/HEAD",            "Git Repository Exposed",           15, "Source code leak via .git/"),
    ("/.git/config",          "Git Config Exposed",               15, ".git/config publicly readable"),
    ("/.env",                 ".env File Exposed",                15, "Environment/secrets file exposed"),
    ("/.env.local",           ".env.local File Exposed",          15, "Local env secrets exposed"),
    ("/.env.production",      ".env.production Exposed",          15, "Production secrets exposed"),
    ("/wp-config.php.bak",    "WordPress Config Backup",          12, "WP config backup exposed"),
    ("/config.php.bak",       "Config Backup Exposed",            12, "Config backup file exposed"),
    ("/backup.zip",           "Backup Archive Exposed",           12, "backup.zip accessible"),
    ("/backup.tar.gz",        "Backup Archive Exposed",           12, "backup.tar.gz accessible"),
    ("/database.sql",         "Database Dump Exposed",            15, "SQL dump file accessible"),
    ("/db.sql",               "Database Dump Exposed",            15, "db.sql accessible"),
    ("/phpinfo.php",          "phpinfo() Exposed",                10, "PHP info page leaks server details"),
    ("/server-status",        "Apache server-status Exposed",      8, "Apache mod_status info exposed"),
    ("/elmah.axd",            "ELMAH Error Log Exposed",           8, "ELMAH error log accessible (ASP.NET)"),
    ("/trace.axd",            "ASP.NET Trace Exposed",             8, "ASP.NET trace handler accessible"),
    ("/robots.txt",           "robots.txt Present",                0, "Informational — robots.txt exists"),
    ("/sitemap.xml",          "sitemap.xml Present",               0, "Informational — sitemap.xml exists"),
    ("/.htaccess",            ".htaccess Exposed",                 8, ".htaccess configuration readable"),
    ("/crossdomain.xml",      "crossdomain.xml Present",           3, "Adobe cross-domain policy found"),
    ("/clientaccesspolicy.xml","clientaccesspolicy.xml Present",   3, "Silverlight cross-domain policy found"),
]


class FileExposureScanner(BaseScanner):
    name = "File Exposure"

    def run(self) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        base = self.target.rstrip("/")

        found_any_critical = False
        for path, label, penalty, description in SENSITIVE_PATHS:
            url = urljoin(base + "/", path.lstrip("/"))
            try:
                resp = self.session.get(url, timeout=10, allow_redirects=False)
            except Exception:
                continue

            status = resp.status_code
            exposed = status == 200 and len(resp.content) > 0

            if penalty == 0:
                # Informational only
                if exposed:
                    result.findings.append(Finding(
                        check_id=f"file_{path.strip('/').replace('.', '_').replace('/', '_')}",
                        category="File Exposure",
                        label=label,
                        passed=True,
                        score=0,
                        max_score=0,
                        detail=f"{description} — HTTP {status}",
                    ))
                continue

            passed = not exposed
            if not passed:
                found_any_critical = True
            result.findings.append(Finding(
                check_id=f"file_{path.strip('/').replace('.', '_').replace('/', '_')}",
                category="File Exposure",
                label=label,
                passed=passed,
                score=penalty if passed else 0,
                max_score=penalty,
                detail=f"{'Accessible' if exposed else 'Not accessible'} — HTTP {status} at {url}",
                recommendation=None if passed else (
                    f"{description}. Block access to this path in your server config "
                    f"(e.g., nginx `deny all;` or Apache `Require all denied`)."
                ),
            ))

        if not result.findings:
            result.findings.append(Finding(
                check_id="file_exposure_none",
                category="File Exposure",
                label="No Sensitive Files Exposed",
                passed=True,
                score=10,
                max_score=10,
                detail="No common sensitive paths are publicly accessible.",
            ))

        return result
