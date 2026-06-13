"""FastAPI backend — wraps the Slopsicurity scanner."""
from dotenv import load_dotenv
load_dotenv()

import asyncio
import json
import os
import smtplib
import time
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import AsyncGenerator, Optional

import requests as req_lib
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel, EmailStr
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from slopsicurity.scanners import ALL_SCANNERS
from slopsicurity.scoring import score_results
from slopsicurity.reporting.json_out import report_to_json
from slopsicurity.reporting.pdf_report import generate_pdf
from slopsicurity.store import save_report, get_report, days_remaining
from slopsicurity.security import (
    SecurityHeadersMiddleware,
    assert_safe_url,
    sanitize_url,
    sanitize_text,
    MAX_NAME_LENGTH,
    MAX_MESSAGE_LENGTH,
)
from main import normalize_url, build_session

# ── App setup ────────────────────────────────────────────────────────────────

limiter = Limiter(key_func=get_remote_address, default_limits=["200/hour"])

app = FastAPI(
    title="Slopsicurity API",
    version="0.1.0",
    # Hide endpoint list from public
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

# Rate limiting
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Security headers (must come before CORS middleware)
app.add_middleware(SecurityHeadersMiddleware)

# CORS — only allow the frontend origin
ALLOWED_ORIGINS = os.getenv(
    "ALLOWED_ORIGINS",
    "http://localhost:5173,http://127.0.0.1:5173"
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
    allow_credentials=False,
)


# ── URL pre-verification ──────────────────────────────────────────────────────

def verify_url(url: str) -> None:
    """
    Checks the URL is reachable before running the full scan.
    Raises HTTPException with a user-friendly message if not.
    """
    import socket
    from urllib.parse import urlparse

    parsed  = urlparse(url)
    hostname = parsed.hostname or ""

    if not hostname or "." not in hostname:
        raise HTTPException(status_code=400, detail="That doesn't look like a real URL.")

    # DNS check
    try:
        socket.setdefaulttimeout(5)
        socket.gethostbyname(hostname)
    except socket.gaierror:
        raise HTTPException(
            status_code=400,
            detail=f"Could not find '{hostname}' — double-check the domain and try again.",
        )

    # Reachability check
    try:
        resp = build_session().get(url, timeout=8, allow_redirects=True)
    except req_lib.exceptions.ConnectionError:
        raise HTTPException(
            status_code=400,
            detail=f"'{hostname}' has a domain registered but no website is running on it. "
                   f"There's nothing to scan.",
        )
    except req_lib.exceptions.Timeout:
        raise HTTPException(
            status_code=400,
            detail=f"'{hostname}' took too long to respond. The site may be down — try again in a moment.",
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Could not reach that URL: {e}")


# ── Pre-flight verify ─────────────────────────────────────────────────────────

@app.get("/scan/verify")
@limiter.limit("30/minute")
def scan_verify(request: Request, url: str):
    """Pre-flight check called by the frontend before opening the SSE stream."""
    try:
        raw = sanitize_url(url)
        clean_url = normalize_url(raw)
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=400, detail="That doesn't look like a valid URL.")

    assert_safe_url(clean_url)
    verify_url(clean_url)
    return {"ok": True, "url": clean_url}


# ── Simple one-shot scan ──────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    url: str

@app.post("/scan")
@limiter.limit("10/minute")
def scan(request: Request, body: ScanRequest):
    raw = sanitize_url(body.url)
    try:
        url = normalize_url(raw)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid URL")

    assert_safe_url(url)
    verify_url(url)

    scan_results = []
    for ScannerClass in ALL_SCANNERS:
        scanner = ScannerClass(target=url, session=build_session())
        scan_results.append(scanner.run())

    report = score_results(url, scan_results)
    return json.loads(report_to_json(report))


# ── Streaming scan (Server-Sent Events) ──────────────────────────────────────

def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


async def _stream_scan(url: str) -> AsyncGenerator[str, None]:
    session = build_session()
    scan_results = []

    yield _sse("start", {"url": url, "total": len(ALL_SCANNERS)})

    for i, ScannerClass in enumerate(ALL_SCANNERS):
        scanner = ScannerClass(target=url, session=session)
        yield _sse("progress", {"index": i, "name": scanner.name, "status": "running"})

        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, scanner.run)
        scan_results.append(result)

        yield _sse("progress", {
            "index": i,
            "name": scanner.name,
            "status": "done",
            "score": result.score,
            "max_score": result.max_score,
            "error": result.error,
        })

    report = score_results(url, scan_results)
    yield _sse("complete", json.loads(report_to_json(report)))


@app.get("/scan/stream")
@limiter.limit("10/minute")
async def scan_stream(request: Request, url: str):
    # verify_url already called by /scan/verify pre-flight
    try:
        clean_url = normalize_url(sanitize_url(url))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid URL")

    assert_safe_url(clean_url)

    return StreamingResponse(
        _stream_scan(clean_url),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok"}


# ── PDF report export ─────────────────────────────────────────────────────────

@app.post("/report/pdf")
@limiter.limit("5/minute")
def report_pdf(request: Request, body: dict):
    """
    Accepts a scan report JSON (same shape as /scan output) and returns a PDF.
    The frontend sends its cached report; no re-scan is needed.
    """
    try:
        pdf_bytes = generate_pdf(body)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {e}")

    url_slug = sanitize_text(body.get("url", "report"), 100)
    import re
    filename = re.sub(r"[^a-zA-Z0-9._-]", "-", url_slug).strip("-")
    filename = f"slopsicurity-{filename[:60]}.pdf"

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ── Share endpoints ───────────────────────────────────────────────────────────

@app.post("/report/share")
@limiter.limit("10/minute")
def report_share(request: Request, body: dict):
    """
    Persist a scan report and return a shareable link ID.
    The client sends the full report JSON; we store it and return the share ID.
    """
    if not body or not body.get("url"):
        raise HTTPException(status_code=400, detail="Invalid report data.")

    try:
        share_id = save_report(body)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Could not save report: {e}")

    base = os.getenv("BASE_URL", "http://localhost:5173")
    return {
        "share_id": share_id,
        "url": f"{base}/?share={share_id}",
        "expires_in_days": 30,
    }


@app.get("/report/share/{share_id}")
@limiter.limit("60/minute")
def report_get_share(request: Request, share_id: str):
    """Return a previously saved report by its share ID."""
    # Validate ID format to avoid DB queries with garbage input
    import re
    if not re.match(r"^[A-Za-z0-9_-]{6,20}$", share_id):
        raise HTTPException(status_code=404, detail="Report not found.")

    data = get_report(share_id)
    if data is None:
        raise HTTPException(status_code=404, detail="Report not found or has expired.")

    days = days_remaining(share_id) or 0
    return {**data, "_share_id": share_id, "_expires_in_days": days}


# ── Contact form ──────────────────────────────────────────────────────────────

class ContactRequest(BaseModel):
    name: str
    email: str
    website: Optional[str] = None
    message: str
    scan_grade: Optional[str] = None
    scan_pct: Optional[float] = None


@app.post("/contact")
@limiter.limit("5/minute")
def contact(request: Request, body: ContactRequest):
    """Sends a contact email via Gmail SMTP."""
    # Sanitize inputs
    name    = sanitize_text(body.name,    MAX_NAME_LENGTH)
    message = sanitize_text(body.message, MAX_MESSAGE_LENGTH)
    email   = sanitize_text(body.email,   254)
    website = sanitize_text(body.website or "", 2048)

    smtp_user = os.getenv("SMTP_USER", "")
    smtp_pass = os.getenv("SMTP_PASS", "")

    if not smtp_user or not smtp_pass:
        raise HTTPException(
            status_code=503,
            detail="Email is not configured on this server.",
        )

    scan_block = ""
    if body.scan_grade:
        scan_block = (
            f"<p><strong>Scan result:</strong> {body.scan_grade} "
            f"({body.scan_pct}%) — {website or 'N/A'}</p><hr/>"
        )

    html_body = (
        f"<p><strong>From:</strong> {name} &lt;{email}&gt;</p>"
        f"<p><strong>Website:</strong> {website or 'N/A'}</p>"
        f"{scan_block}"
        f"<p style='white-space:pre-wrap'>{message}</p>"
    )

    msg = MIMEMultipart("alternative")
    msg["Subject"]  = f"[Slopsicurity] Contact from {name}"
    msg["From"]     = smtp_user
    msg["To"]       = "slopsicurity@gmail.com"
    msg["Reply-To"] = email
    msg.attach(MIMEText(html_body, "html"))

    try:
        with smtplib.SMTP("smtp.gmail.com", 587, timeout=10) as server:
            server.ehlo()
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.sendmail(smtp_user, "slopsicurity@gmail.com", msg.as_string())
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to send email: {e}")

    return {"status": "sent"}
