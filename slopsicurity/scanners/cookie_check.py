"""Cookie security flags scanner — checks HttpOnly, Secure, and SameSite."""
from .base import BaseScanner, Finding, ScanResult


class CookieScanner(BaseScanner):
    name = "Cookie Security"

    def run(self) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        try:
            resp = self.session.get(self.target, timeout=15, allow_redirects=True)
        except Exception as e:
            result.error = str(e)
            return result

        # urllib3 keeps duplicate headers; requests collapses them.
        # Use the raw response to get every Set-Cookie line separately.
        try:
            raw_cookies = resp.raw.headers.getlist("Set-Cookie")
        except AttributeError:
            raw_cookies = [
                v for k, v in resp.raw.headers.items()
                if k.lower() == "set-cookie"
            ]

        if not raw_cookies:
            result.findings.append(Finding(
                check_id="cookie_none",
                category="Cookie Security",
                label="No Cookies Set",
                passed=True,
                score=0,
                max_score=0,
                detail="No Set-Cookie headers found on this response.",
            ))
            return result

        # Parse each Set-Cookie header
        parsed = []
        for raw in raw_cookies:
            parts = [p.strip() for p in raw.split(";")]
            name = parts[0].split("=")[0].strip() if parts else "unknown"
            attrs_lower = {p.lower().split("=")[0].strip() for p in parts[1:]}
            parsed.append({
                "name": name,
                "httponly": "httponly" in attrs_lower,
                "secure":   "secure"   in attrs_lower,
                "samesite": any(a.startswith("samesite") for a in attrs_lower),
            })

        count = len(parsed)

        # HttpOnly — prevents JS from reading session cookies (XSS mitigation)
        missing_httponly = [c["name"] for c in parsed if not c["httponly"]]
        ok = not missing_httponly
        result.findings.append(Finding(
            check_id="cookie_httponly",
            category="Cookie Security",
            label="Cookies: HttpOnly Flag",
            passed=ok,
            score=4 if ok else 0,
            max_score=4,
            detail=(
                f"All {count} cookie(s) have HttpOnly"
                if ok else
                f"Missing HttpOnly on: {', '.join(missing_httponly[:5])}"
                + (" (and more)" if len(missing_httponly) > 5 else "")
            ),
            recommendation=None if ok else (
                "Set the HttpOnly flag on all session cookies so JavaScript cannot read them. "
                "Example: Set-Cookie: session=abc; HttpOnly; Secure; SameSite=Strict"
            ),
        ))

        # Secure — ensures cookies are never sent over plain HTTP
        missing_secure = [c["name"] for c in parsed if not c["secure"]]
        ok = not missing_secure
        result.findings.append(Finding(
            check_id="cookie_secure",
            category="Cookie Security",
            label="Cookies: Secure Flag",
            passed=ok,
            score=3 if ok else 0,
            max_score=3,
            detail=(
                f"All {count} cookie(s) have Secure"
                if ok else
                f"Missing Secure on: {', '.join(missing_secure[:5])}"
                + (" (and more)" if len(missing_secure) > 5 else "")
            ),
            recommendation=None if ok else (
                "Add the Secure flag so cookies are only sent over HTTPS. "
                "Example: Set-Cookie: session=abc; HttpOnly; Secure; SameSite=Strict"
            ),
        ))

        # SameSite — CSRF protection
        missing_samesite = [c["name"] for c in parsed if not c["samesite"]]
        ok = not missing_samesite
        result.findings.append(Finding(
            check_id="cookie_samesite",
            category="Cookie Security",
            label="Cookies: SameSite Flag",
            passed=ok,
            score=3 if ok else 0,
            max_score=3,
            detail=(
                f"All {count} cookie(s) have SameSite"
                if ok else
                f"Missing SameSite on: {', '.join(missing_samesite[:5])}"
                + (" (and more)" if len(missing_samesite) > 5 else "")
            ),
            recommendation=None if ok else (
                "Set SameSite=Strict or SameSite=Lax to prevent cross-site request forgery (CSRF). "
                "Example: Set-Cookie: session=abc; HttpOnly; Secure; SameSite=Strict"
            ),
        ))

        return result
