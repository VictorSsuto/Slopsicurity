"""
Professional PDF report generator using reportlab.
Produces a clean one-pager suitable for handing to a developer or client.
"""
import io
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

PAGE_W, PAGE_H = A4
MARGIN = 18 * mm

# ── Colour helpers ────────────────────────────────────────────────────────────
C_PASS    = colors.HexColor("#22c55e")
C_FAIL    = colors.HexColor("#ef4444")
C_WARN    = colors.HexColor("#f59e0b")
C_GRAY    = colors.HexColor("#e5e5e5")
C_LIGHT   = colors.HexColor("#f7f7f7")
C_DARK    = colors.HexColor("#111111")
C_MUTED   = colors.HexColor("#555555")
C_BORDER  = colors.HexColor("#cccccc")

HEX_PASS = "#22c55e"
HEX_FAIL = "#ef4444"
HEX_WARN = "#f59e0b"
HEX_DARK = "#111111"
HEX_MUTED = "#555555"


def _grade_hex(grade: str) -> str:
    if grade in ("A+", "A"):
        return HEX_PASS
    if grade in ("B", "C"):
        return HEX_WARN
    return HEX_FAIL


def _grade_color(grade: str):
    if grade in ("A+", "A"):
        return C_PASS
    if grade in ("B", "C"):
        return C_WARN
    return C_FAIL


def _s(name, parent_style, **kw):
    """Helper: create a ParagraphStyle from another ParagraphStyle object."""
    return ParagraphStyle(name, parent=parent_style, **kw)


def generate_pdf(report_data: dict) -> bytes:
    """
    Generate a PDF from the JSON report dict (same shape as /scan output).
    Returns raw PDF bytes.
    """
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=MARGIN,
        rightMargin=MARGIN,
        topMargin=MARGIN,
        bottomMargin=MARGIN,
        title="Slopsicurity Security Report",
        author="Slopsicurity",
    )

    base_styles = getSampleStyleSheet()
    normal = base_styles["Normal"]

    # ── Styles ────────────────────────────────────────────────────────────────
    s_normal     = _s("sn",  normal, fontSize=9,  leading=13, textColor=C_DARK)
    s_small      = _s("ssm", normal, fontSize=7,  leading=10, textColor=C_MUTED)
    s_label      = _s("slb", normal, fontSize=7,  leading=10, textColor=C_MUTED,
                       fontName="Helvetica-Bold", tracking=60)
    s_url        = _s("sur", normal, fontSize=9,  leading=12, textColor=C_MUTED,
                       fontName="Courier")
    s_grade      = _s("sgr", normal, fontSize=48, leading=52, fontName="Helvetica-Bold")
    s_grade_desc = _s("sgd", normal, fontSize=8,  leading=11, textColor=C_MUTED)
    s_score_big  = _s("ssb", normal, fontSize=22, leading=26, fontName="Helvetica-Bold",
                       textColor=C_DARK)
    s_score_pct  = _s("ssp", normal, fontSize=13, leading=16, textColor=C_MUTED,
                       fontName="Courier")
    s_section    = _s("ssc", normal, fontSize=7,  leading=10, fontName="Helvetica-Bold",
                       textColor=C_MUTED, spaceBefore=8, spaceAfter=4, tracking=80)
    s_reco_num   = _s("srn", normal, fontSize=8,  leading=11, textColor=C_MUTED,
                       fontName="Courier")
    s_reco_label = _s("srl", normal, fontSize=9,  leading=12, fontName="Helvetica-Bold",
                       textColor=C_DARK)
    s_reco_pts   = _s("srp", normal, fontSize=8,  leading=11, textColor=colors.HexColor(HEX_FAIL),
                       fontName="Courier", alignment=2)
    s_reco_text  = _s("srt", normal, fontSize=8,  leading=11, textColor=C_MUTED,
                       leftIndent=8*mm)
    s_snippet    = _s("sni", normal, fontSize=7,  leading=10, fontName="Courier",
                       textColor=C_MUTED, leftIndent=8*mm, backColor=C_LIGHT,
                       borderColor=C_BORDER, borderWidth=0.5, borderPad=4)
    s_find       = _s("sfn", normal, fontSize=8,  leading=11, textColor=C_DARK)
    s_find_det   = _s("sfd", normal, fontSize=7,  leading=10, textColor=C_MUTED,
                       fontName="Courier")
    s_footer     = _s("sft", normal, fontSize=7,  leading=9,  textColor=C_MUTED, alignment=1)
    s_pf         = _s("spf", normal, fontSize=9,  leading=12, textColor=C_DARK)

    # ── Data ──────────────────────────────────────────────────────────────────
    score    = report_data["score"]
    grade    = score["grade"]
    pct      = score["percentage"]
    total    = score["total"]
    maxs     = score["max"]
    url      = report_data["url"]
    recos    = report_data["recommendations"]
    scanners = report_data["scanners"]
    date_str = datetime.utcnow().strftime("%B %d, %Y")

    passes = sum(
        1 for sc in scanners for f in sc["findings"]
        if f["passed"] and f["max_score"] > 0
    )
    fails = len(recos)

    story = []
    content_width = PAGE_W - 2 * MARGIN

    # ── Header ────────────────────────────────────────────────────────────────
    hdr = Table(
        [[
            Paragraph("SLOPSICURITY", _s("h1", normal, fontSize=11,
                                          fontName="Helvetica-Bold", textColor=C_DARK)),
            Paragraph(f"Security Report  |  {date_str}",
                      _s("h2", normal, fontSize=8, textColor=C_MUTED, alignment=2)),
        ]],
        colWidths=[content_width * 0.55, content_width * 0.45],
    )
    hdr.setStyle(TableStyle([
        ("VALIGN",      (0, 0), (-1, -1), "MIDDLE"),
        ("LINEBELOW",   (0, 0), (-1, -1), 0.5, C_GRAY),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 6),
    ]))
    story.append(hdr)
    story.append(Spacer(1, 5*mm))

    # ── URL ───────────────────────────────────────────────────────────────────
    story.append(Paragraph("SCANNED URL", s_label))
    story.append(Paragraph(url, s_url))
    story.append(Spacer(1, 5*mm))

    # ── Score block ───────────────────────────────────────────────────────────
    grade_color_hex = _grade_hex(grade)
    grade_para = Paragraph(
        f'<font color="{grade_color_hex}" name="Helvetica-Bold">{grade}</font>',
        s_grade,
    )
    desc_para  = Paragraph(score["grade_description"], s_grade_desc)
    score_para = Paragraph(f"{total} / {maxs}", s_score_big)
    pct_para   = Paragraph(f"{pct}%", s_score_pct)
    pf_para    = Paragraph(
        f'<font color="{HEX_PASS}">+ {passes} passed</font>'
        f'   '
        f'<font color="{HEX_FAIL}">- {fails} failed</font>',
        s_pf,
    )

    score_tbl = Table(
        [
            [grade_para, score_para],
            ["",         pct_para],
            [desc_para,  pf_para],
        ],
        colWidths=[28*mm, content_width - 28*mm],
    )
    score_tbl.setStyle(TableStyle([
        ("VALIGN",         (0, 0), (-1, -1), "TOP"),
        ("SPAN",           (0, 0), (0, 1)),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [C_LIGHT]),
        ("BOX",            (0, 0), (-1, -1), 0.5, C_GRAY),
        ("TOPPADDING",     (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING",  (0, 0), (-1, -1), 6),
        ("LEFTPADDING",    (0, 0), (-1, -1), 10),
    ]))
    story.append(score_tbl)
    story.append(Spacer(1, 6*mm))

    # ── Recommendations ───────────────────────────────────────────────────────
    if recos:
        story.append(Paragraph("RECOMMENDATIONS", s_section))
        story.append(HRFlowable(width="100%", thickness=0.5, color=C_GRAY, spaceAfter=4))

        for i, r in enumerate(recos):
            row = Table(
                [[
                    Paragraph(str(i + 1).zfill(2), s_reco_num),
                    Paragraph(r["label"], s_reco_label),
                    Paragraph(f'-{r["impact_points"]} pts', s_reco_pts),
                ]],
                colWidths=[8*mm, content_width - 30*mm, 22*mm],
            )
            row.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP")]))
            story.append(row)

            if r.get("recommendation"):
                story.append(Paragraph(r["recommendation"], s_reco_text))

            if r.get("code_snippet"):
                snippet = (r["code_snippet"]
                           .replace("&", "&amp;")
                           .replace("<", "&lt;")
                           .replace(">", "&gt;")
                           .replace("\n", "<br/>"))
                story.append(Paragraph(snippet, s_snippet))

            story.append(Spacer(1, 3*mm))

    # ── Findings by scanner ───────────────────────────────────────────────────
    story.append(Paragraph("FINDINGS BY SCANNER", s_section))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_GRAY, spaceAfter=4))

    for sc in scanners:
        real_findings = [f for f in sc["findings"] if f["max_score"] > 0]
        if not real_findings and not sc.get("error"):
            continue

        sc_score = f'{sc["score"]}/{sc["max_score"]}' if sc["max_score"] > 0 else "info"
        sc_hdr = Table(
            [[
                Paragraph(sc["name"], _s("scn", normal, fontSize=9,
                                         fontName="Helvetica-Bold", textColor=C_DARK)),
                Paragraph(sc_score, _s("scs", normal, fontSize=8, fontName="Courier",
                                        textColor=C_MUTED, alignment=2)),
            ]],
            colWidths=[content_width - 20*mm, 20*mm],
        )
        sc_hdr.setStyle(TableStyle([
            ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING",   (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 2),
            ("LINEBELOW",    (0, 0), (-1, -1), 0.3, C_GRAY),
        ]))
        story.append(sc_hdr)

        if sc.get("error"):
            story.append(Paragraph(f"Error: {sc['error']}", s_small))

        for f in real_findings:
            icon  = "PASS" if f["passed"] else "FAIL"
            icol  = HEX_PASS if f["passed"] else HEX_FAIL
            pts   = f'+{f["score"]}' if f["passed"] else f'0/{f["max_score"]}'

            f_row = Table(
                [[
                    Paragraph(f'<font color="{icol}">{icon}</font>',
                               _s("fi", normal, fontSize=6, fontName="Helvetica-Bold",
                                  leading=9)),
                    Paragraph(f["label"], s_find),
                    Paragraph(pts, _s("fp", normal, fontSize=7, fontName="Courier",
                                       textColor=C_MUTED, alignment=2)),
                ]],
                colWidths=[10*mm, content_width - 25*mm, 15*mm],
            )
            f_row.setStyle(TableStyle([
                ("VALIGN",       (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING",   (0, 0), (-1, -1), 2),
                ("BOTTOMPADDING",(0, 0), (-1, -1), 2),
            ]))
            story.append(f_row)

        story.append(Spacer(1, 3*mm))

    # ── Footer ────────────────────────────────────────────────────────────────
    story.append(Spacer(1, 4*mm))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_GRAY, spaceAfter=4))
    story.append(Paragraph(
        "For informational purposes only. Not a substitute for a professional security audit. "
        "Results may be incomplete or inaccurate. Generated by Slopsicurity.",
        s_footer,
    ))

    doc.build(story)
    return buf.getvalue()
