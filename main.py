"""
main.py
Audit AI Copilot v3 — FastAPI backend
Features: Document upload (PDF/DOCX) + Rule engine + LLM + PDF report export
"""

from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from openai import OpenAI
import json
import os
import io
from datetime import datetime
from dotenv import load_dotenv

from audit_engine import analyze_process, format_for_llm

load_dotenv()

app = FastAPI(title="Audit AI Copilot API", version="3.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
analysis_history = []


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class AnalysisRequest(BaseModel):
    process: str


class FollowUpRequest(BaseModel):
    process: str
    previous_analysis: dict
    question: str


# ---------------------------------------------------------------------------
# Document text extraction
# ---------------------------------------------------------------------------

def extract_text_from_pdf(file_bytes: bytes) -> str:
    try:
        from pypdf import PdfReader
        reader = PdfReader(io.BytesIO(file_bytes))
        text = " ".join(
            page.extract_text() or "" for page in reader.pages
        )
        return text.strip()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"PDF extraction failed: {str(e)}")


def extract_text_from_docx(file_bytes: bytes) -> str:
    try:
        from docx import Document
        doc = Document(io.BytesIO(file_bytes))
        text = " ".join(p.text for p in doc.paragraphs if p.text.strip())
        return text.strip()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"DOCX extraction failed: {str(e)}")


# ---------------------------------------------------------------------------
# LLM enhancement
# ---------------------------------------------------------------------------

LLM_SYSTEM_PROMPT = """You are a senior internal auditor at a global investment bank.

You will receive structured audit findings from a rule-based engine. Your job is to:
1. Enhance each finding with precise professional audit language
2. Add business impact and regulatory implications (Basel III, SOX, MiFID II, DORA, ISO 31000)
3. Preserve ALL findings — do not remove or merge any

ALWAYS respond with ONLY valid JSON, no markdown, no code fences.

Return exactly this structure:
{
  "risks": [
    {"id": "R1", "title": "Short title", "description": "Refined description", "severity": "High|Medium|Low"}
  ],
  "control_gaps": [
    {"id": "CG1", "title": "Short title", "description": "Refined description", "severity": "High|Medium|Low"}
  ],
  "recommended_controls": [
    {"id": "RC1", "title": "Control name", "description": "Specific action", "framework": "COSO|SOX|Basel|ISO31000|MiFID II"}
  ],
  "overall_severity": "High|Medium|Low",
  "business_impact": {
    "summary": "2-3 sentence executive summary",
    "financial_exposure": "Estimated exposure or qualitative range",
    "regulatory_implications": "Key regulatory concerns",
    "reputational_risk": "High|Medium|Low"
  },
  "audit_opinion": "One sentence professional audit opinion"
}"""


def enhance_with_llm(process: str, engine_output: str) -> dict:
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": LLM_SYSTEM_PROMPT},
            {"role": "user", "content": (
                f"ORIGINAL PROCESS:\n{process}\n\n"
                f"{engine_output}\n\n"
                "Enhance these findings and return structured JSON."
            )}
        ],
        temperature=0.3,
        max_tokens=2000,
        response_format={"type": "json_object"}
    )
    return json.loads(response.choices[0].message.content)


def build_fallback_response(engine_result) -> dict:
    return {
        "risks": [
            {"id": f"R{i+1}", "title": f.rule_id, "description": f.risk, "severity": f.severity}
            for i, f in enumerate(engine_result.findings)
        ],
        "control_gaps": [
            {"id": f"CG{i+1}", "title": f.rule_id, "description": f.gap, "severity": f.severity}
            for i, f in enumerate(engine_result.findings)
        ],
        "recommended_controls": [
            {"id": f"RC{i+1}", "title": "Recommended Control", "description": c, "framework": "ISO31000"}
            for i, c in enumerate(engine_result.controls)
        ],
        "overall_severity": engine_result.severity,
        "business_impact": {
            "summary": f"{engine_result.rule_count} control deficiencies identified. Immediate review recommended.",
            "financial_exposure": "Assessment unavailable — LLM offline.",
            "regulatory_implications": "Review against SOX, Basel III, ISO 31000.",
            "reputational_risk": engine_result.severity,
        },
        "audit_opinion": f"Rule engine detected {engine_result.rule_count} findings with {engine_result.severity} overall severity.",
        "llm_enhanced": False,
    }


# ---------------------------------------------------------------------------
# PDF Report Generator
# ---------------------------------------------------------------------------

def generate_pdf_report(process: str, result: dict) -> bytes:
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.colors import HexColor, white, black
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
        from reportlab.lib.units import cm
        from reportlab.lib.enums import TA_LEFT, TA_CENTER

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer, pagesize=A4,
            rightMargin=2*cm, leftMargin=2*cm,
            topMargin=2*cm, bottomMargin=2*cm
        )

        # Colors
        dark_bg    = HexColor("#080c14")
        emerald    = HexColor("#10b981")
        red        = HexColor("#ef4444")
        amber      = HexColor("#f59e0b")
        blue       = HexColor("#3b82f6")
        gray_text  = HexColor("#6b7280")
        light_text = HexColor("#374151")

        styles = getSampleStyleSheet()

        def style(name, **kwargs):
            return ParagraphStyle(name, **kwargs)

        title_style   = style("Title2",   fontSize=20, textColor=dark_bg,   fontName="Helvetica-Bold", spaceAfter=4)
        sub_style     = style("Sub",      fontSize=9,  textColor=gray_text,  fontName="Helvetica",      spaceAfter=16)
        section_style = style("Section",  fontSize=11, textColor=dark_bg,    fontName="Helvetica-Bold", spaceBefore=14, spaceAfter=6)
        body_style    = style("Body2",    fontSize=9,  textColor=light_text, fontName="Helvetica",      spaceAfter=4, leading=14)
        opinion_style = style("Opinion",  fontSize=10, textColor=light_text, fontName="Helvetica-Oblique", spaceAfter=8, leading=15)

        sev = result.get("overall_severity", "Unknown")
        sev_color = {"High": red, "Medium": amber, "Low": blue}.get(sev, gray_text)

        elements = []

        # Header
        elements.append(Paragraph("AUDIT AI COPILOT", title_style))
        elements.append(Paragraph(f"Internal Audit Risk Assessment  ·  Generated {datetime.utcnow().strftime('%d %b %Y, %H:%M UTC')}", sub_style))
        elements.append(HRFlowable(width="100%", thickness=1, color=emerald, spaceAfter=16))

        # Severity banner
        sev_data = [[
            Paragraph("OVERALL SEVERITY", style("sl", fontSize=8, textColor=gray_text, fontName="Helvetica-Bold")),
            Paragraph(sev.upper(), style("sv", fontSize=13, textColor=sev_color, fontName="Helvetica-Bold")),
            Paragraph("AUDIT OPINION", style("ol", fontSize=8, textColor=gray_text, fontName="Helvetica-Bold")),
        ]]
        sev_table = Table(sev_data, colWidths=[3.5*cm, 3*cm, 11*cm])
        sev_table.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,-1), HexColor("#f9fafb")),
            ("BOX", (0,0), (-1,-1), 0.5, HexColor("#e5e7eb")),
            ("TOPPADDING", (0,0), (-1,-1), 10),
            ("BOTTOMPADDING", (0,0), (-1,-1), 10),
            ("LEFTPADDING", (0,0), (-1,-1), 12),
        ]))
        elements.append(sev_table)
        elements.append(Spacer(1, 6))
        elements.append(Paragraph(result.get("audit_opinion", ""), opinion_style))
        elements.append(HRFlowable(width="100%", thickness=0.5, color=HexColor("#e5e7eb"), spaceAfter=12))

        # Process snippet
        elements.append(Paragraph("PROCESS ANALYZED", section_style))
        snippet = process[:400] + ("..." if len(process) > 400 else "")
        elements.append(Paragraph(snippet, body_style))
        elements.append(Spacer(1, 8))

        # Risks
        elements.append(HRFlowable(width="100%", thickness=0.5, color=HexColor("#e5e7eb"), spaceAfter=8))
        elements.append(Paragraph(f"RISKS IDENTIFIED  ({len(result.get('risks', []))})", section_style))
        for risk in result.get("risks", []):
            sc = {"High": red, "Medium": amber, "Low": blue}.get(risk.get("severity",""), gray_text)
            row = [[
                Paragraph(f"<font color='#{sc.hexval()[2:]}'>●</font> [{risk.get('severity','').upper()}]  {risk.get('title','')}",
                          style(f"rt{risk['id']}", fontSize=9, fontName="Helvetica-Bold", textColor=dark_bg, leading=13)),
            ]]
            t = Table(row, colWidths=[16.5*cm])
            t.setStyle(TableStyle([
                ("BACKGROUND", (0,0), (-1,-1), HexColor("#fef2f2")),
                ("LEFTPADDING", (0,0), (-1,-1), 10),
                ("TOPPADDING", (0,0), (-1,-1), 7),
                ("BOTTOMPADDING", (0,0), (-1,-1), 4),
            ]))
            elements.append(t)
            elements.append(Paragraph(risk.get("description",""), body_style))
            elements.append(Spacer(1, 4))

        # Control Gaps
        elements.append(HRFlowable(width="100%", thickness=0.5, color=HexColor("#e5e7eb"), spaceAfter=8))
        elements.append(Paragraph(f"CONTROL GAPS  ({len(result.get('control_gaps', []))})", section_style))
        for gap in result.get("control_gaps", []):
            row = [[Paragraph(f"▲ [{gap.get('severity','').upper()}]  {gap.get('title','')}",
                              style(f"gt{gap['id']}", fontSize=9, fontName="Helvetica-Bold", textColor=dark_bg))]]
            t = Table(row, colWidths=[16.5*cm])
            t.setStyle(TableStyle([
                ("BACKGROUND", (0,0), (-1,-1), HexColor("#fffbeb")),
                ("LEFTPADDING", (0,0), (-1,-1), 10),
                ("TOPPADDING", (0,0), (-1,-1), 7),
                ("BOTTOMPADDING", (0,0), (-1,-1), 4),
            ]))
            elements.append(t)
            elements.append(Paragraph(gap.get("description",""), body_style))
            elements.append(Spacer(1, 4))

        # Recommended Controls
        elements.append(HRFlowable(width="100%", thickness=0.5, color=HexColor("#e5e7eb"), spaceAfter=8))
        elements.append(Paragraph(f"RECOMMENDED CONTROLS  ({len(result.get('recommended_controls', []))})", section_style))
        for ctrl in result.get("recommended_controls", []):
            fw = ctrl.get("framework", "")
            row = [[Paragraph(f"✓  {ctrl.get('title','')}  [{fw}]",
                              style(f"ct{ctrl['id']}", fontSize=9, fontName="Helvetica-Bold", textColor=HexColor("#065f46")))]]
            t = Table(row, colWidths=[16.5*cm])
            t.setStyle(TableStyle([
                ("BACKGROUND", (0,0), (-1,-1), HexColor("#f0fdf4")),
                ("LEFTPADDING", (0,0), (-1,-1), 10),
                ("TOPPADDING", (0,0), (-1,-1), 7),
                ("BOTTOMPADDING", (0,0), (-1,-1), 4),
            ]))
            elements.append(t)
            elements.append(Paragraph(ctrl.get("description",""), body_style))
            elements.append(Spacer(1, 4))

        # Business Impact
        elements.append(HRFlowable(width="100%", thickness=0.5, color=HexColor("#e5e7eb"), spaceAfter=8))
        elements.append(Paragraph("BUSINESS IMPACT", section_style))
        bi = result.get("business_impact", {})
        impact_data = [
            ["Summary",                bi.get("summary", "")],
            ["Financial Exposure",     bi.get("financial_exposure", "")],
            ["Regulatory Implications",bi.get("regulatory_implications", "")],
            ["Reputational Risk",      bi.get("reputational_risk", "")],
        ]
        impact_table = Table(
            [[Paragraph(k, style(f"ik{i}", fontSize=8, fontName="Helvetica-Bold", textColor=gray_text)),
              Paragraph(v, style(f"iv{i}", fontSize=9, fontName="Helvetica", textColor=light_text, leading=13))]
             for i, (k, v) in enumerate(impact_data)],
            colWidths=[4.5*cm, 12*cm]
        )
        impact_table.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,-1), HexColor("#f9fafb")),
            ("BOX", (0,0), (-1,-1), 0.5, HexColor("#e5e7eb")),
            ("INNERGRID", (0,0), (-1,-1), 0.3, HexColor("#e5e7eb")),
            ("TOPPADDING", (0,0), (-1,-1), 8),
            ("BOTTOMPADDING", (0,0), (-1,-1), 8),
            ("LEFTPADDING", (0,0), (-1,-1), 10),
        ]))
        elements.append(impact_table)

        # Footer
        elements.append(Spacer(1, 20))
        elements.append(HRFlowable(width="100%", thickness=0.5, color=HexColor("#e5e7eb")))
        elements.append(Paragraph(
            "Generated by Audit AI Copilot · For internal use only · Not a substitute for professional audit engagement",
            style("footer", fontSize=7, textColor=gray_text, fontName="Helvetica", alignment=TA_CENTER, spaceBefore=6)
        ))

        doc.build(elements)
        return buffer.getvalue()

    except ImportError:
        raise HTTPException(status_code=500, detail="reportlab not installed. Add it to requirements.txt.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {str(e)}")


# ---------------------------------------------------------------------------
# Core analysis pipeline (shared by text + upload endpoints)
# ---------------------------------------------------------------------------

def run_analysis_pipeline(process: str) -> tuple[dict, bool]:
    """Returns (result_dict, llm_enhanced)."""
    engine_result = analyze_process(process)
    engine_summary = format_for_llm(engine_result)
    try:
        result = enhance_with_llm(process, engine_summary)
        result["llm_enhanced"] = True
        return result, True
    except Exception:
        return build_fallback_response(engine_result), False


def save_to_history(process: str, result: dict, llm_enhanced: bool) -> int:
    entry = {
        "id": len(analysis_history) + 1,
        "timestamp": datetime.utcnow().isoformat(),
        "process_snippet": process[:120] + ("..." if len(process) > 120 else ""),
        "overall_severity": result.get("overall_severity", "Unknown"),
        "rule_count": len(result.get("risks", [])),
        "llm_enhanced": llm_enhanced,
        "result": result,
        "process": process,
    }
    analysis_history.insert(0, entry)
    if len(analysis_history) > 20:
        analysis_history.pop()
    return entry["id"]


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.post("/analyze")
async def analyze(request: AnalysisRequest):
    if not request.process or len(request.process.strip()) < 20:
        raise HTTPException(status_code=400, detail="Process description too short. Minimum 20 characters.")
    if len(request.process) > 5000:
        raise HTTPException(status_code=400, detail="Process description too long. Maximum 5000 characters.")

    result, llm_enhanced = run_analysis_pipeline(request.process)
    analysis_id = save_to_history(request.process, result, llm_enhanced)
    return {"success": True, "data": result, "analysis_id": analysis_id}


@app.post("/upload")
async def upload_document(file: UploadFile = File(...)):
    """Accept PDF or DOCX, extract text, run full analysis pipeline."""
    filename = file.filename or ""
    if not (filename.endswith(".pdf") or filename.endswith(".docx")):
        raise HTTPException(status_code=400, detail="Only PDF and DOCX files are supported.")

    file_bytes = await file.read()
    if len(file_bytes) > 10 * 1024 * 1024:  # 10MB limit
        raise HTTPException(status_code=400, detail="File too large. Maximum 10MB.")

    if filename.endswith(".pdf"):
        process_text = extract_text_from_pdf(file_bytes)
    else:
        process_text = extract_text_from_docx(file_bytes)

    if not process_text or len(process_text.strip()) < 20:
        raise HTTPException(status_code=400, detail="Could not extract sufficient text from the document.")

    # Truncate to 5000 chars for LLM
    process_text = process_text[:5000]

    result, llm_enhanced = run_analysis_pipeline(process_text)
    analysis_id = save_to_history(process_text, result, llm_enhanced)
    return {
        "success": True,
        "data": result,
        "analysis_id": analysis_id,
        "extracted_chars": len(process_text),
        "filename": filename,
    }


@app.post("/report/{analysis_id}")
async def download_report(analysis_id: int):
    """Generate and return a PDF report for a completed analysis."""
    entry = next((h for h in analysis_history if h["id"] == analysis_id), None)
    if not entry:
        raise HTTPException(status_code=404, detail="Analysis not found.")

    pdf_bytes = generate_pdf_report(entry["process"], entry["result"])
    filename = f"audit-report-{analysis_id}-{datetime.utcnow().strftime('%Y%m%d')}.pdf"

    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@app.post("/followup")
async def follow_up(request: FollowUpRequest):
    if not request.question.strip():
        raise HTTPException(status_code=400, detail="Question cannot be empty.")
    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are a senior internal auditor. Answer follow-up questions about an audit analysis concisely and professionally. Maximum 3 paragraphs."},
                {"role": "user", "content": f"Original process:\n{request.process}\n\nAudit analysis:\n{json.dumps(request.previous_analysis, indent=2)}\n\nQuestion: {request.question}"}
            ],
            temperature=0.4,
            max_tokens=600,
        )
        return {"success": True, "answer": response.choices[0].message.content}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Follow-up failed: {str(e)}")


@app.get("/history")
async def get_history():
    return {
        "success": True,
        "data": [
            {
                "id": h["id"],
                "timestamp": h["timestamp"],
                "process_snippet": h["process_snippet"],
                "overall_severity": h["overall_severity"],
                "rule_count": h["rule_count"],
                "llm_enhanced": h["llm_enhanced"],
            }
            for h in analysis_history
        ],
    }


@app.get("/history/{analysis_id}")
async def get_analysis(analysis_id: int):
    entry = next((h for h in analysis_history if h["id"] == analysis_id), None)
    if not entry:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    return {"success": True, "data": entry}


@app.get("/health")
async def health():
    return {"status": "ok", "version": "3.0.0", "rules": 10, "features": ["upload", "pdf-export", "followup"]}

