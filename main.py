"""
main.py
Audit AI Copilot — FastAPI backend
Flow: Rule Engine → LLM Enhancement → Structured Response
LLM failure is non-fatal; rule engine output is always returned.
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from openai import OpenAI
import json
import os
from datetime import datetime
from dotenv import load_dotenv

from audit_engine import analyze_process, format_for_llm

load_dotenv()

app = FastAPI(title="Audit AI Copilot API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Restrict to your Vercel domain in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# In-memory history (replace with DB in production)
analysis_history = []


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class AnalysisRequest(BaseModel):
    process: str


class FollowUpRequest(BaseModel):
    process: str
    previous_analysis: dict
    question: str


# ---------------------------------------------------------------------------
# LLM enhancement prompt
# ---------------------------------------------------------------------------

LLM_SYSTEM_PROMPT = """You are a senior internal auditor at a global investment bank.

You will receive structured audit findings from a rule-based engine. Your job is to:
1. Enhance and refine each finding with professional audit language
2. Add business impact for each risk
3. Add regulatory implications where relevant (Basel III, SOX, MiFID II, DORA, ISO 31000)
4. Preserve ALL findings — do not remove or merge any

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


def enhance_with_llm(process: str, engine_output: str, engine_severity: str) -> dict:
    """
    Pass rule-engine findings to LLM for enhancement.
    Returns enhanced JSON dict. Raises on failure — caller handles fallback.
    """
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": LLM_SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"ORIGINAL PROCESS:\n{process}\n\n"
                    f"{engine_output}\n\n"
                    f"Enhance these findings and return structured JSON."
                )
            }
        ],
        temperature=0.3,
        max_tokens=2000,
        response_format={"type": "json_object"}
    )
    return json.loads(response.choices[0].message.content)


def build_fallback_response(process: str, engine_result) -> dict:
    """
    Construct a valid response directly from rule-engine output.
    Used when LLM is unavailable or fails.
    """
    sev_map = {"High": "High", "Medium": "Medium", "Low": "Low"}

    risks = [
        {"id": f"R{i+1}", "title": f.rule_id, "description": f.risk, "severity": f.severity}
        for i, f in enumerate(engine_result.findings)
    ]
    gaps = [
        {"id": f"CG{i+1}", "title": f.rule_id, "description": f.gap, "severity": f.severity}
        for i, f in enumerate(engine_result.findings)
    ]
    controls = [
        {"id": f"RC{i+1}", "title": "Recommended Control", "description": c, "framework": "ISO31000"}
        for i, c in enumerate(engine_result.controls)
    ]

    return {
        "risks": risks,
        "control_gaps": gaps,
        "recommended_controls": controls,
        "overall_severity": engine_result.severity,
        "business_impact": {
            "summary": f"{engine_result.rule_count} control deficiencies identified. Immediate review recommended.",
            "financial_exposure": "Not assessed — LLM enhancement unavailable.",
            "regulatory_implications": "Review against applicable frameworks (SOX, Basel III, ISO 31000).",
            "reputational_risk": sev_map.get(engine_result.severity, "Medium"),
        },
        "audit_opinion": f"Rule engine detected {engine_result.rule_count} findings with {engine_result.severity} overall severity.",
        "llm_enhanced": False,
    }


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.post("/analyze")
async def analyze(request: AnalysisRequest):
    if not request.process or len(request.process.strip()) < 20:
        raise HTTPException(status_code=400, detail="Process description too short. Minimum 20 characters.")
    if len(request.process) > 5000:
        raise HTTPException(status_code=400, detail="Process description too long. Maximum 5000 characters.")

    # Step 1: Rule engine — always runs, never skipped
    engine_result = analyze_process(request.process)
    engine_summary = format_for_llm(engine_result)

    # Step 2: LLM enhancement — non-fatal fallback if it fails
    llm_enhanced = True
    try:
        result = enhance_with_llm(request.process, engine_summary, engine_result.severity)
        result["llm_enhanced"] = True
    except Exception as llm_error:
        result = build_fallback_response(request.process, engine_result)
        llm_enhanced = False

    # Step 3: Store in history
    entry = {
        "id": len(analysis_history) + 1,
        "timestamp": datetime.utcnow().isoformat(),
        "process_snippet": request.process[:120] + ("..." if len(request.process) > 120 else ""),
        "overall_severity": result.get("overall_severity", engine_result.severity),
        "rule_count": engine_result.rule_count,
        "llm_enhanced": llm_enhanced,
        "result": result,
    }
    analysis_history.insert(0, entry)
    if len(analysis_history) > 20:
        analysis_history.pop()

    return {"success": True, "data": result, "analysis_id": entry["id"]}


@app.post("/followup")
async def follow_up(request: FollowUpRequest):
    if not request.question.strip():
        raise HTTPException(status_code=400, detail="Question cannot be empty.")

    try:
        context = json.dumps(request.previous_analysis, indent=2)
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a senior internal auditor. Answer follow-up questions about "
                        "an audit analysis concisely and professionally. Use precise audit and "
                        "financial terminology. Maximum 3 paragraphs."
                    )
                },
                {
                    "role": "user",
                    "content": (
                        f"Original process:\n{request.process}\n\n"
                        f"Audit analysis:\n{context}\n\n"
                        f"Question: {request.question}"
                    )
                }
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
    return {"status": "ok", "version": "2.0.0", "engine": "rule-based + llm"}

- Ensure rules always run (even if LLM fails)
