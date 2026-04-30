"""
pdf_report.py
Generates a branded PDF audit report from analysis results.
Uses reportlab — no external fonts or assets required.
"""

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, KeepTogether
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from datetime import datetime
import io


# ---------------------------------------------------------------------------
# Colour palette
# ---------------------------------------------------------------------------

BLACK       = colors.HexColor("#0a0a0a")
WHITE       = colors.HexColor("#ffffff")
DARK_BG     = colors.HexColor("#0f1923")
EMERALD     = colors.HexColor("#10b981")
EMERALD_LT  = colors.HexColor("#d1fae5")
RED         = colors.HexColor("#ef4444")
RED_LT      = colors.HexColor("#fee2e2")
AMBER       = colors.HexColor("#f59e0b")
AMBER_LT    = colors.HexColor("#fef3c7")
BLUE        = colors.HexColor("#3b82f6")
BLUE_LT     = colors.HexColor("#dbeafe")
GREY        = colors.HexColor("#6b7280")
GREY_LT     = colors.HexColor("#f3f4f6")
BORDER      = colors.HexColor("#e5e7eb")


SEV_COLORS = {
    "High":   (RED,    RED_LT),
    "Medium": (AMBER,  AMBER_LT),
    "Low":    (BLUE,   BLUE_LT),
}


# ---------------------------------------------------------------------------
# Style helpers
# ---------------------------------------------------------------------------

def _styles():
    base = getSampleStyleSheet()
    custom = {}

    custom["title"] = ParagraphStyle(
        "title", parent=base["Normal"],
        fontSize=22, textColor=WHITE, fontName="Helvetica-Bold",
        spaceAfter=2, alignment=TA_LEFT,
    )
    custom["subtitle"] = ParagraphStyle(
        "subtitle", parent=base["Normal"],
        fontSize=9, textColor=colors.HexColor("#94a3b8"),
        fontName="Helvetica", spaceAfter=0, alignment=TA_LEFT,
        letterSpacing=2,
    )
    custom["section"] = ParagraphStyle(
        "section", parent=base["Normal"],
        fontSize=10, textColor=GREY, fontName="Helvetica-Bold",
        spaceBefore=14, spaceAfter=6, letterSpacing=1.5,
    )
    custom["body"] = ParagraphStyle(
        "body", parent=base["Normal"],
        fontSize=9, textColor=BLACK, fontName="Helvetica",
        leading=14, spaceAfter=4,
    )
    custom["body_white"] = ParagraphStyle(
        "body_white", parent=base["Normal"],
        fontSize=9, textColor=WHITE, fontName="Helvetica",
        leading=14,
    )
    custom["opinion"] = ParagraphStyle(
        "opinion", parent=base["Normal"],
        fontSize=10, textColor=colors.HexColor("#1e293b"),
        fontName="Helvetica-Oblique", leading=16, spaceAfter=0,
    )
    custom["small"] = ParagraphStyle(
        "small", parent=base["Normal"],
        fontSize=8, textColor=GREY, fontName="Helvetica", leading=12,
    )
    custom["card_title"] = ParagraphStyle(
        "card_title", parent=base["Normal"],
        fontSize=9, textColor=BLACK, fontName="Helvetica-Bold", spaceAfter=3,
    )
    custom["card_body"] = ParagraphStyle(
        "card_body", parent=base["Normal"],
        fontSize=8, textColor=colors.HexColor("#374151"),
        fontName="Helvetica", leading=12,
    )

    return custom


# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------

def _header_block(data: dict, styles: dict) -> list:
    """Dark header with title + metadata."""
    timestamp = datetime.utcnow().strftime("%d %B %Y · %H:%M UTC")
    sev = data.get("overall_severity", "Unknown")
    sev_color, _ = SEV_COLORS.get(sev, (GREY, GREY_LT))

    header_data = [[
        Paragraph("AUDIT AI COPILOT", styles["title"]),
        Paragraph(f"SEVERITY: {sev.upper()}", ParagraphStyle(
            "sev", fontSize=11, textColor=sev_color,
            fontName="Helvetica-Bold", alignment=TA_RIGHT,
        )),
    ]]
    header_table = Table(header_data, colWidths=["70%", "30%"])
    header_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), DARK_BG),
        ("TOPPADDING",    (0, 0), (-1, -1), 18),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING",   (0, 0), (-1, -1), 20),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 20),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))

    sub_data = [[
        Paragraph("INTERNAL AUDIT RISK ASSESSMENT REPORT", styles["subtitle"]),
        Paragraph(timestamp, ParagraphStyle(
            "ts", fontSize=8, textColor=colors.HexColor("#64748b"),
            fontName="Helvetica", alignment=TA_RIGHT,
        )),
    ]]
    sub_table = Table(sub_data, colWidths=["70%", "30%"])
    sub_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), DARK_BG),
        ("TOPPADDING",    (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 18),
        ("LEFTPADDING",   (0, 0), (-1, -1), 20),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 20),
    ]))

    return [header_table, sub_table]


def _opinion_block(data: dict, styles: dict) -> list:
    opinion = data.get("audit_opinion", "No audit opinion available.")
    table = Table(
        [[Paragraph(f'"{opinion}"', styles["opinion"])]],
        colWidths=["100%"],
    )
    table.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("LEFTPADDING",   (0, 0), (-1, -1), 16),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 16),
        ("TOPPADDING",    (0, 0), (-1, -1), 14),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 14),
        ("BOX", (0, 0), (-1, -1), 1, BORDER),
        ("LINEBEFORE", (0, 0), (0, -1), 3, EMERALD),
    ]))
    return [Spacer(1, 6), table]


def _stats_block(data: dict, styles: dict) -> list:
    risks    = data.get("risks", [])
    gaps     = data.get("control_gaps", [])
    controls = data.get("recommended_controls", [])
    high     = sum(1 for r in risks if r.get("severity") == "High")
    sev      = data.get("overall_severity", "?")
    sev_color, _ = SEV_COLORS.get(sev, (GREY, GREY_LT))

    def stat_cell(value, label, color):
        return [
            Paragraph(str(value), ParagraphStyle(
                "sv", fontSize=20, textColor=color,
                fontName="Helvetica-Bold", alignment=TA_CENTER,
            )),
            Paragraph(label, ParagraphStyle(
                "sl", fontSize=7, textColor=GREY,
                fontName="Helvetica", alignment=TA_CENTER, letterSpacing=1,
            )),
        ]

    stats = Table(
        [[stat_cell(len(risks), "RISKS", RED),
          stat_cell(high, "HIGH SEVERITY", RED),
          stat_cell(len(gaps), "CONTROL GAPS", AMBER),
          stat_cell(len(controls), "CONTROLS REC.", EMERALD)]],
        colWidths=["25%", "25%", "25%", "25%"],
    )
    stats.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), GREY_LT),
        ("TOPPADDING",    (0, 0), (-1, -1), 12),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
        ("BOX", (0, 0), (-1, -1), 1, BORDER),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    return [Spacer(1, 10), stats]


def _finding_card(item: dict, color: colors.Color, bg: colors.Color, styles: dict) -> Table:
    sev = item.get("severity", "")
    sev_c, sev_bg = SEV_COLORS.get(sev, (GREY, GREY_LT))
    title = item.get("title", item.get("id", ""))
    desc  = item.get("description", "")
    fw    = item.get("framework", "")

    right_content = Paragraph(sev.upper(), ParagraphStyle(
        "badge", fontSize=7, textColor=sev_c,
        fontName="Helvetica-Bold", alignment=TA_CENTER,
    ))

    header_row = [[
        Paragraph(f'<b>{item.get("id", "")}  {title}</b>', styles["card_title"]),
        right_content,
    ]]
    header = Table(header_row, colWidths=["85%", "15%"])
    header.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), bg),
        ("TOPPADDING",    (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
        ("BACKGROUND",    (1, 0), (1, 0), sev_bg),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))

    fw_text = f"  [{fw}]" if fw else ""
    body_row = [[Paragraph(desc + fw_text, styles["card_body"])]]
    body = Table(body_row, colWidths=["100%"])
    body.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), WHITE),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
    ]))

    wrapper = Table([[header], [body]], colWidths=["100%"])
    wrapper.setStyle(TableStyle([
        ("BOX",        (0, 0), (-1, -1), 1, color),
        ("LINEBEFORE", (0, 0), (0, -1), 3, color),
        ("TOPPADDING",    (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
    ]))
    return wrapper


def _impact_block(data: dict, styles: dict) -> list:
    impact = data.get("business_impact", {})
    rows = [
        ["Financial Exposure", impact.get("financial_exposure", "—")],
        ["Regulatory Implications", impact.get("regulatory_implications", "—")],
        ["Reputational Risk", impact.get("reputational_risk", "—")],
    ]

    def make_row(label, value):
        return [
            Paragraph(label, ParagraphStyle(
                "il", fontSize=8, textColor=GREY,
                fontName="Helvetica-Bold", letterSpacing=0.5,
            )),
            Paragraph(value, styles["card_body"]),
        ]

    table_data = [make_row(r[0], r[1]) for r in rows]
    summary = impact.get("summary", "")

    t = Table(table_data, colWidths=["30%", "70%"])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), WHITE),
        ("BACKGROUND",    (0, 0), (0, -1), GREY_LT),
        ("TOPPADDING",    (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
        ("INNERGRID",     (0, 0), (-1, -1), 0.5, BORDER),
        ("BOX",           (0, 0), (-1, -1), 1, BORDER),
    ]))

    return [
        Paragraph(summary, styles["body"]),
        Spacer(1, 6),
        t,
    ]


def _footer_line(styles: dict) -> list:
    return [
        Spacer(1, 16),
        HRFlowable(width="100%", thickness=0.5, color=BORDER),
        Spacer(1, 4),
        Paragraph(
            "Generated by Audit AI Copilot · Confidential · For internal use only · "
            f"{datetime.utcnow().strftime('%d %b %Y')}",
            ParagraphStyle("footer", fontSize=7, textColor=GREY,
                           fontName="Helvetica", alignment=TA_CENTER),
        ),
    ]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_pdf(data: dict, process_text: str = "") -> bytes:
    """
    Generate a PDF audit report from analysis data.
    Returns raw PDF bytes ready to stream.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        leftMargin=18*mm, rightMargin=18*mm,
        topMargin=10*mm, bottomMargin=18*mm,
    )

    styles = _styles()
    story = []

    # Header
    story.extend(_header_block(data, styles))
    story.append(Spacer(1, 10))

    # Audit opinion
    story.extend(_opinion_block(data, styles))
    story.append(Spacer(1, 6))

    # Stats
    story.extend(_stats_block(data, styles))
    story.append(Spacer(1, 14))

    # Risks
    risks = data.get("risks", [])
    if risks:
        story.append(Paragraph("● RISKS IDENTIFIED", styles["section"]))
        story.append(HRFlowable(width="100%", thickness=0.5, color=RED))
        story.append(Spacer(1, 6))
        for r in risks:
            story.append(KeepTogether([
                _finding_card(r, RED, RED_LT, styles),
                Spacer(1, 6),
            ]))

    # Control Gaps
    gaps = data.get("control_gaps", [])
    if gaps:
        story.append(Paragraph("● CONTROL GAPS", styles["section"]))
        story.append(HRFlowable(width="100%", thickness=0.5, color=AMBER))
        story.append(Spacer(1, 6))
        for g in gaps:
            story.append(KeepTogether([
                _finding_card(g, AMBER, AMBER_LT, styles),
                Spacer(1, 6),
            ]))

    # Recommended Controls
    controls = data.get("recommended_controls", [])
    if controls:
        story.append(Paragraph("● RECOMMENDED CONTROLS", styles["section"]))
        story.append(HRFlowable(width="100%", thickness=0.5, color=EMERALD))
        story.append(Spacer(1, 6))
        for c in controls:
            story.append(KeepTogether([
                _finding_card(c, EMERALD, EMERALD_LT, styles),
                Spacer(1, 6),
            ]))

    # Business Impact
    story.append(Paragraph("● BUSINESS IMPACT", styles["section"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=BLUE))
    story.append(Spacer(1, 6))
    story.extend(_impact_block(data, styles))

    # Process snippet
    if process_text:
        story.append(Spacer(1, 10))
        story.append(Paragraph("● PROCESS ANALYZED", styles["section"]))
        snippet = process_text[:500] + ("..." if len(process_text) > 500 else "")
        story.append(Paragraph(snippet, styles["small"]))

    # Footer
    story.extend(_footer_line(styles))

    doc.build(story)
    return buffer.getvalue()
