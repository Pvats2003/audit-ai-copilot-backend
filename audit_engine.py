"""
audit_engine.py
Rule-based audit detection engine for Audit AI Copilot.
Runs deterministically — no LLM dependency.
"""

import re
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Control Library — single source of truth for all recommended controls
# ---------------------------------------------------------------------------

CONTROL_LIBRARY = {
    "segregation": "Implement maker-checker mechanism with separate roles for initiation, approval, and execution.",
    "audit_trail": "Enable comprehensive logging and monitoring with tamper-proof audit trail and retention policy.",
    "approval":    "Add mandatory approval workflow with documented authorization matrix and escalation path.",
    "automation":  "Automate validation checks to eliminate manual intervention and reduce human error risk.",
    "redundancy":  "Implement failover systems with active-passive replication and documented recovery procedures.",
}


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class AuditFinding:
    rule_id: str
    risk: str
    gap: str
    control: str
    severity: str                          # High | Medium | Low (per-finding)
    matched_keywords: list = field(default_factory=list)


@dataclass
class AuditResult:
    findings: list
    risks: list
    gaps: list
    controls: list
    severity: str                          # Overall: High | Medium | Low
    rule_count: int


# ---------------------------------------------------------------------------
# Individual rule checkers
# ---------------------------------------------------------------------------

def _check_segregation_of_duties(text: str) -> Optional[AuditFinding]:
    """Detects when a single actor performs multiple conflicting steps."""
    patterns = [
        r"\bsame (person|user|individual|employee|actor|operator)\b",
        r"\bsingle (person|user|individual|employee|actor|operator)\b",
        r"\bone person\b",
        r"\bsame .{0,30}(approves?|authorizes?|reviews?|enters?)\b",
        r"\b(approves?|authorizes?) and (enters?|submits?|executes?)\b",
        r"\bno separat\w+\b",
        r"\bwithout separat\w+\b",
    ]
    matched = [p for p in patterns if re.search(p, text, re.IGNORECASE)]
    if not matched:
        return None
    return AuditFinding(
        rule_id="SOD-001",
        risk="Lack of segregation of duties — single actor controls multiple conflicting steps, creating fraud and error risk.",
        gap="Same actor handles initiation, processing, and authorization without independent oversight.",
        control=CONTROL_LIBRARY["segregation"],
        severity="High",
        matched_keywords=matched,
    )


def _check_missing_approval(text: str) -> Optional[AuditFinding]:
    """Detects absence of an approval or authorization workflow."""
    approval_keywords = [
        r"\bapprov\w+\b", r"\bauthoriz\w+\b", r"\bsign.?off\b",
        r"\bsanction\w*\b", r"\bclearance\b", r"\bvalidat\w+\b",
        r"\breview\w*\b", r"\bchecker\b",
    ]
    found = any(re.search(kw, text, re.IGNORECASE) for kw in approval_keywords)
    if found:
        return None
    return AuditFinding(
        rule_id="APR-001",
        risk="Unauthorized activity risk — no approval or authorization mechanism detected in the process.",
        gap="Process lacks a defined approval workflow, permitting transactions to proceed without oversight.",
        control=CONTROL_LIBRARY["approval"],
        severity="High",
        matched_keywords=[],
    )


def _check_missing_audit_trail(text: str) -> Optional[AuditFinding]:
    """Detects absence of logging, tracking, or audit trail."""
    trail_keywords = [
        r"\blog\w*\b", r"\btrack\w*\b", r"\bhistory\b", r"\brecord\w*\b",
        r"\btrace\w*\b", r"\baudit trail\b", r"\bmonitor\w*\b",
        r"\bjournal\w*\b", r"\barchive\w*\b",
    ]
    found = any(re.search(kw, text, re.IGNORECASE) for kw in trail_keywords)
    if found:
        return None
    return AuditFinding(
        rule_id="TRC-001",
        risk="Lack of traceability — no audit trail means transactions cannot be reconstructed or investigated post-event.",
        gap="No logging or monitoring mechanism identified; regulatory record-keeping requirements likely unmet.",
        control=CONTROL_LIBRARY["audit_trail"],
        severity="Medium",
        matched_keywords=[],
    )


def _check_manual_process(text: str) -> Optional[AuditFinding]:
    """Detects manual processes prone to human error."""
    patterns = [
        r"\bmanual\w*\b", r"\bhand.?written\b", r"\bspreadsheet\b",
        r"\bemail\w*\b", r"\bphone\b", r"\bverbally?\b",
        r"\bpaper.?based\b", r"\bby hand\b", r"\bphysical form\b",
    ]
    matched = [p for p in patterns if re.search(p, text, re.IGNORECASE)]
    if not matched:
        return None
    return AuditFinding(
        rule_id="MAN-001",
        risk="Human error risk — manual steps introduce data entry mistakes, omissions, and inconsistent execution.",
        gap="Manual intervention points identified with no automated validation or error-detection controls.",
        control=CONTROL_LIBRARY["automation"],
        severity="Medium",
        matched_keywords=matched,
    )


def _check_single_point_of_failure(text: str) -> Optional[AuditFinding]:
    """Detects single points of failure with no redundancy."""
    patterns = [
        r"\bsingle system\b", r"\bone server\b", r"\bno backup\b",
        r"\bno redundan\w+\b", r"\bno failover\b", r"\bno disaster recovery\b",
        r"\bno DR\b", r"\bno replicat\w+\b", r"\bno fall.?back\b",
        r"\bsingle point\b",
    ]
    matched = [p for p in patterns if re.search(p, text, re.IGNORECASE)]
    if not matched:
        return None
    return AuditFinding(
        rule_id="SPF-001",
        risk="System failure risk — single point of failure with no redundancy could cause critical process outage.",
        gap="No failover, backup, or disaster recovery mechanism identified for critical system components.",
        control=CONTROL_LIBRARY["redundancy"],
        severity="High",
        matched_keywords=matched,
    )


# ---------------------------------------------------------------------------
# Severity calculator
# ---------------------------------------------------------------------------

def _calculate_severity(findings: list) -> str:
    high_count = sum(1 for f in findings if f.severity == "High")
    if high_count >= 2 or len(findings) >= 3:
        return "High"
    if len(findings) == 2:
        return "Medium"
    return "Low"


# ---------------------------------------------------------------------------
# All registered rules — add new rules here
# ---------------------------------------------------------------------------

RULES = [
    _check_segregation_of_duties,
    _check_missing_approval,
    _check_missing_audit_trail,
    _check_manual_process,
    _check_single_point_of_failure,
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_process(process: str) -> AuditResult:
    """
    Run all audit rules against the process description.
    Always completes — individual rule failures are silently skipped.
    """
    text = process.strip()
    findings = []

    for rule in RULES:
        try:
            finding = rule(text)
            if finding:
                findings.append(finding)
        except Exception:
            continue  # Rule failure must never crash the engine

    return AuditResult(
        findings=findings,
        risks=[f.risk for f in findings],
        gaps=[f.gap for f in findings],
        controls=list(dict.fromkeys(f.control for f in findings)),  # deduplicated, order-preserved
        severity=_calculate_severity(findings),
        rule_count=len(findings),
    )


def format_for_llm(result: AuditResult) -> str:
    """Serialize rule-engine output into a prompt-ready block for LLM enhancement."""
    lines = ["=== RULE ENGINE FINDINGS ===\n"]

    lines.append("RISKS DETECTED:")
    for i, r in enumerate(result.risks, 1):
        lines.append(f"  R{i}. {r}")

    lines.append("\nCONTROL GAPS:")
    for i, g in enumerate(result.gaps, 1):
        lines.append(f"  CG{i}. {g}")

    lines.append("\nRECOMMENDED CONTROLS:")
    for i, c in enumerate(result.controls, 1):
        lines.append(f"  RC{i}. {c}")

    lines.append(f"\nOVERALL SEVERITY: {result.severity}")
    lines.append(f"RULES TRIGGERED: {result.rule_count}")

    return "\n".join(lines)
