"""FastAPI backend — wraps the Slopsicurity scanner."""
import asyncio
import json
import os
import smtplib
import time
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import AsyncGenerator, Optional

import requests as req_lib
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from slopsicurity.scanners import ALL_SCANNERS
from slopsicurity.scoring import score_results
from slopsicurity.reporting.json_out import report_to_json
from main import normalize_url, build_session

app = FastAPI(title="Slopsicurity API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    url: str


# ── Simple one-shot scan ──────────────────────────────────────────────────────

@app.post("/scan")
def scan(body: ScanRequest):
    try:
        url = normalize_url(body.url)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid URL")

    session = build_session()
    scan_results = []

    for ScannerClass in ALL_SCANNERS:
        scanner = ScannerClass(target=url, session=session)
        scan_results.append(scanner.run())

    report = score_results(url, scan_results)
    return json.loads(report_to_json(report))


# ── Streaming scan (Server-Sent Events) ──────────────────────────────────────

def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


async def _stream_scan(url: str) -> AsyncGenerator[str, None]:
    session = build_session()
    scan_results = []
    total = len(ALL_SCANNERS)

    yield _sse("start", {"url": url, "total": total})

    for i, ScannerClass in enumerate(ALL_SCANNERS):
        scanner = ScannerClass(target=url, session=session)
        yield _sse("progress", {
            "index": i,
            "name": scanner.name,
            "status": "running",
        })

        # Run the (blocking) scanner in a thread pool so we don't block the event loop
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
async def scan_stream(url: str):
    try:
        clean_url = normalize_url(url)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid URL")

    return StreamingResponse(
        _stream_scan(clean_url),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/health")
def health():
    return {"status": "ok"}


# ── Contact form ──────────────────────────────────────────────────────────────

class ContactRequest(BaseModel):
    name: str
    email: str
    website: Optional[str] = None
    message: str
    scan_grade: Optional[str] = None
    scan_pct: Optional[float] = None


@app.post("/contact")
def contact(body: ContactRequest):
    """
    Sends a contact email to the Slopsicurity team.

    Configure via environment variables:
        SMTP_HOST     — SMTP server (default: smtp.gmail.com)
        SMTP_PORT     — SMTP port   (default: 587)
        SMTP_USER     — Sender email address
        SMTP_PASS     — Sender email password / app password
        CONTACT_EMAIL — Recipient email (default: same as SMTP_USER)
    """
    smtp_host  = os.getenv("SMTP_HOST", "smtp.gmail.com")
    smtp_port  = int(os.getenv("SMTP_PORT", "587"))
    smtp_user  = os.getenv("SMTP_USER", "")
    smtp_pass  = os.getenv("SMTP_PASS", "")
    contact_to = os.getenv("CONTACT_EMAIL", "slopsicurity@gmail.com")

    if not smtp_user or not smtp_pass:
        # No SMTP configured — fail gracefully with a helpful message
        raise HTTPException(
            status_code=503,
            detail=(
                "Email sending is not configured. "
                "Set SMTP_USER, SMTP_PASS, and CONTACT_EMAIL environment variables."
            ),
        )

    # Build email
    scan_line = ""
    if body.scan_grade:
        scan_line = f"\nScan result: {body.scan_grade} ({body.scan_pct}%) — {body.website or 'N/A'}\n"

    plain_body = (
        f"From: {body.name} <{body.email}>\n"
        f"Website: {body.website or 'N/A'}"
        f"{scan_line}\n"
        f"---\n\n"
        f"{body.message}"
    )

    html_body = f"""
    <p><strong>From:</strong> {body.name} &lt;{body.email}&gt;</p>
    <p><strong>Website:</strong> {body.website or 'N/A'}</p>
    {"<p><strong>Scan:</strong> " + body.scan_grade + " (" + str(body.scan_pct) + "%) — " + (body.website or "N/A") + "</p>" if body.scan_grade else ""}
    <hr/>
    <p style="white-space:pre-wrap">{body.message}</p>
    """

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"[Slopsicurity] Contact from {body.name}"
    msg["From"]    = smtp_user
    msg["To"]      = contact_to
    msg["Reply-To"] = body.email

    msg.attach(MIMEText(plain_body, "plain"))
    msg.attach(MIMEText(html_body, "html"))

    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
            server.ehlo()
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.sendmail(smtp_user, contact_to, msg.as_string())
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to send email: {e}")

    return {"status": "sent"}
