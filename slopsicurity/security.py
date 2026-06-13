"""
Security hardening for the Slopsicurity API.
Covers: security headers, SSRF protection, input sanitization.
"""
import ipaddress
import re
import socket
from urllib.parse import urlparse

from fastapi import HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


# ── Security Headers Middleware ───────────────────────────────────────────────

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Adds every security header that Slopsicurity itself audits for.
    Practise what we preach.
    """
    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)

        # HSTS — force HTTPS for 1 year, include subdomains
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains; preload"
        )
        # CSP — lock down what can run on the page
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "font-src 'self'; "
            "object-src 'none'; "
            "frame-ancestors 'none';"
        )
        # Clickjacking protection
        response.headers["X-Frame-Options"] = "DENY"
        # MIME sniffing protection
        response.headers["X-Content-Type-Options"] = "nosniff"
        # Referrer policy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        # Permissions policy — disable unused browser features
        response.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=(), "
            "payment=(), usb=(), interest-cohort=()"
        )
        # Legacy XSS protection
        response.headers["X-XSS-Protection"] = "1; mode=block"
        # Remove server fingerprinting headers
        for h in ("server", "x-powered-by"):
            if h in response.headers:
                del response.headers[h]

        return response


# ── SSRF Protection ───────────────────────────────────────────────────────────

# Hostnames that are never valid scan targets
_BLOCKED_HOSTNAMES = {
    "localhost", "broadcasthost",
    "ip6-localhost", "ip6-loopback",
}

# Patterns that indicate internal/private hostnames
_PRIVATE_PATTERNS = re.compile(
    r"(^|\.)("
    r"local|internal|intranet|corp|lan|home|private"
    r")$",
    re.IGNORECASE,
)


def _is_private_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_reserved
            or addr.is_unspecified
        )
    except ValueError:
        return False


def assert_safe_url(url: str) -> None:
    """
    Raises HTTPException if the URL targets an internal/private resource.
    Prevents Server-Side Request Forgery (SSRF) attacks.
    """
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower().strip()

    if not hostname:
        raise HTTPException(status_code=400, detail="Invalid URL — no hostname found.")

    # Block known internal hostnames
    if hostname in _BLOCKED_HOSTNAMES:
        raise HTTPException(
            status_code=400,
            detail=f"'{hostname}' is not a public URL.",
        )

    # Block private hostname patterns
    if _PRIVATE_PATTERNS.search(hostname):
        raise HTTPException(
            status_code=400,
            detail=f"'{hostname}' looks like an internal address and cannot be scanned.",
        )

    # Block raw IP addresses (also prevents direct private IP targeting)
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname):
        raise HTTPException(
            status_code=400,
            detail="IP addresses are not supported — please enter a domain name.",
        )

    # Resolve and check the actual IP
    try:
        resolved_ip = socket.gethostbyname(hostname)
        if _is_private_ip(resolved_ip):
            raise HTTPException(
                status_code=400,
                detail=(
                    f"'{hostname}' resolves to a private IP address and cannot be scanned."
                ),
            )
    except socket.gaierror:
        # DNS failure — will be caught later by verify_url
        pass


# ── Input Sanitization ────────────────────────────────────────────────────────

MAX_URL_LENGTH = 2048
MAX_MESSAGE_LENGTH = 5000
MAX_NAME_LENGTH = 120


def sanitize_url(raw: str) -> str:
    raw = raw.strip()
    if len(raw) > MAX_URL_LENGTH:
        raise HTTPException(status_code=400, detail="URL is too long.")
    # Strip null bytes and control characters
    raw = re.sub(r"[\x00-\x1f\x7f]", "", raw)
    return raw


def sanitize_text(raw: str, max_len: int = MAX_MESSAGE_LENGTH) -> str:
    raw = raw.strip()
    if len(raw) > max_len:
        raise HTTPException(status_code=400, detail="Input is too long.")
    raw = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", raw)
    return raw
