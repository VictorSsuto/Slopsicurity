"""SSL/TLS certificate and HTTPS checks."""
import ssl
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse

from .base import BaseScanner, Finding, ScanResult


class SSLScanner(BaseScanner):
    name = "SSL/TLS"

    def run(self) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        parsed = urlparse(self.target)
        hostname = parsed.hostname
        port = parsed.port or 443

        # 1. HTTPS enforced
        uses_https = parsed.scheme == "https"
        result.findings.append(Finding(
            check_id="ssl_https",
            category="SSL/TLS",
            label="HTTPS Enforced",
            passed=uses_https,
            score=15 if uses_https else 0,
            max_score=15,
            detail="Site uses HTTPS" if uses_https else "Site does not use HTTPS",
            recommendation=None if uses_https else (
                "Redirect all HTTP traffic to HTTPS. "
                "Obtain a free certificate from Let's Encrypt."
            ),
        ))

        if not uses_https:
            return result

        # Grab the certificate
        cert_info = self._fetch_cert(hostname, port)
        if cert_info is None:
            result.findings.append(Finding(
                check_id="ssl_cert_valid",
                category="SSL/TLS",
                label="Certificate Valid",
                passed=False,
                score=0,
                max_score=10,
                detail="Could not retrieve certificate — connection failed or cert is invalid.",
                recommendation="Ensure a valid, trusted SSL certificate is installed.",
            ))
            return result

        cert, protocol = cert_info

        # 2. Certificate not expired
        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        now = datetime.now(tz=timezone.utc)
        days_left = (not_after - now).days
        cert_valid = days_left > 0
        result.findings.append(Finding(
            check_id="ssl_cert_valid",
            category="SSL/TLS",
            label="Certificate Valid & Not Expired",
            passed=cert_valid,
            score=10 if cert_valid else 0,
            max_score=10,
            detail=f"Certificate expires in {days_left} days ({not_after.date()})" if cert_valid
                   else f"Certificate expired {abs(days_left)} days ago",
            recommendation=None if cert_valid else "Renew your SSL certificate immediately.",
        ))

        # 3. Certificate expiry warning (< 30 days)
        expiry_ok = days_left > 30
        result.findings.append(Finding(
            check_id="ssl_cert_expiry",
            category="SSL/TLS",
            label="Certificate Expiry > 30 Days",
            passed=expiry_ok,
            score=5 if expiry_ok else 0,
            max_score=5,
            detail=f"{days_left} days remaining" if cert_valid else "Already expired",
            recommendation=None if expiry_ok else (
                f"Certificate expires in {days_left} days. Renew soon to avoid downtime."
            ),
        ))

        # 4. Modern TLS version
        modern_tls = protocol in ("TLSv1.2", "TLSv1.3")
        result.findings.append(Finding(
            check_id="ssl_tls_version",
            category="SSL/TLS",
            label="Modern TLS Version (1.2+)",
            passed=modern_tls,
            score=10 if modern_tls else 0,
            max_score=10,
            detail=f"Negotiated protocol: {protocol}",
            recommendation=None if modern_tls else (
                "Disable TLS 1.0 and 1.1 on your server. Enable TLS 1.2 and 1.3 only."
            ),
        ))

        return result

    def _fetch_cert(self, hostname: str, port: int):
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    protocol = ssock.version()
                    return cert, protocol
        except Exception:
            return None
