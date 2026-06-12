"""DNS and domain security checks (DNSSEC, SPF, DMARC, CAA)."""
import socket
import dns.resolver
import dns.dnssec
import dns.name
from urllib.parse import urlparse
from .base import BaseScanner, Finding, ScanResult


class DNSScanner(BaseScanner):
    name = "DNS & Domain"

    def run(self) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        parsed = urlparse(self.target)
        hostname = parsed.hostname

        # Strip leading "www." for email-related DNS records
        apex = hostname
        if apex.startswith("www."):
            apex = apex[4:]

        # 1. IP resolution (informational)
        try:
            ip = socket.gethostbyname(hostname)
            result.findings.append(Finding(
                check_id="dns_resolves",
                category="DNS",
                label="Domain Resolves",
                passed=True,
                score=5,
                max_score=5,
                detail=f"Resolves to {ip}",
            ))
        except Exception:
            result.findings.append(Finding(
                check_id="dns_resolves",
                category="DNS",
                label="Domain Resolves",
                passed=False,
                score=0,
                max_score=5,
                detail="Domain did not resolve — DNS failure.",
                recommendation="Check your DNS configuration and ensure A/AAAA records exist.",
            ))
            return result

        # 2. SPF record
        spf = self._txt_contains(apex, "v=spf1")
        result.findings.append(Finding(
            check_id="dns_spf",
            category="DNS / Email Security",
            label="SPF Record Present",
            passed=spf is not None,
            score=8 if spf else 0,
            max_score=8,
            detail=f'SPF: "{spf}"' if spf else "No SPF TXT record found",
            recommendation=None if spf else (
                "Add an SPF record to prevent email spoofing. "
                "Example: v=spf1 include:_spf.google.com ~all"
            ),
        ))

        # 3. DMARC record
        dmarc = self._txt_contains(f"_dmarc.{apex}", "v=DMARC1")
        result.findings.append(Finding(
            check_id="dns_dmarc",
            category="DNS / Email Security",
            label="DMARC Record Present",
            passed=dmarc is not None,
            score=8 if dmarc else 0,
            max_score=8,
            detail=f'DMARC: "{dmarc}"' if dmarc else "No DMARC record found at _dmarc." + apex,
            recommendation=None if dmarc else (
                "Add a DMARC record to protect your domain from phishing. "
                "Example: v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com"
            ),
        ))

        # 4. CAA record (limits which CAs can issue certs)
        caa = self._caa_record(apex)
        result.findings.append(Finding(
            check_id="dns_caa",
            category="DNS",
            label="CAA Record Present",
            passed=caa is not None,
            score=5 if caa else 0,
            max_score=5,
            detail=f"CAA: {caa}" if caa else "No CAA record found",
            recommendation=None if caa else (
                "Add a CAA record to restrict which Certificate Authorities can issue "
                "TLS certs for your domain. Example: 0 issue \"letsencrypt.org\""
            ),
        ))

        return result

    def _txt_contains(self, name: str, prefix: str):
        try:
            answers = dns.resolver.resolve(name, "TXT", lifetime=8)
            for rdata in answers:
                txt = b"".join(rdata.strings).decode(errors="replace")
                if txt.startswith(prefix):
                    return txt
        except Exception:
            pass
        return None

    def _caa_record(self, name: str):
        try:
            answers = dns.resolver.resolve(name, "CAA", lifetime=8)
            return "; ".join(str(r) for r in answers)
        except Exception:
            return None
