"""
audit_engine.py
Rule-based audit detection engine — 10 rules across 6 domains.
Deterministic, no LLM dependency, always completes.
"""

import re
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Control Library
# ---------------------------------------------------------------------------

CONTROL_LIBRARY = {
    "segregation":   "Implement maker-checker mechanism with separate roles for initiation, approval, and execution.",
    "audit_trail":   "Enable comprehensive logging and monitoring with tamper-proof audit trail and retention policy.",
    "approval":      "Add mandatory approval workflow with documented authorization matrix and escalation path.",
    "automation":    "Automate validation checks to eliminate manual intervention and reduce human error risk.",
    "redundancy":    "Implement failover systems with active-passive replication and documented recovery procedures.",
    "encryption":    "Enforce data encryption at rest (AES-256) and in transit (TLS 1.2+) with key management policy.",
    "access":        "Implement role-based access control (RBAC) with MFA, least-privilege principles, and quarterly access reviews.",
    "contract":      "Establish formal written agreements with SLAs, liability clauses, and dispute resolution procedures.",
    "limits":        "Define and enforce transaction limits, velocity controls, and threshold breach escalation procedures.",
    "testing":       "Implement mandatory UAT, regression testing, and change management approval before production deployment.",
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
    severity: str
    matched_keywords: list = field(default_factory=list)


@dataclass
class AuditResult:
    findings: list
    risks: list
    gaps: list
    controls: list
    severity: str
    rule_count: int


# ---------------------------------------------------------------------------
# Rules 1-5: Original
# ---------------------------------------------------------------------------

def _check_segregation_of_duties(text: str) -> Optional[AuditFinding]:
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
        risk="Lack of segregation of duties — single actor controls multiple conflicting steps, enabling fraud and undetected errors.",
        gap="Same actor handles initiation, processing, and authorization without independent oversight.",
        control=CONTROL_LIBRARY["segregation"],
        severity="High",
        matched_keywords=matched,
    )


def _check_missing_approval(text: str) -> Optional[AuditFinding]:
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
        risk="Lack of traceability — transactions cannot be reconstructed or investigated post-event.",
        gap="No logging or monitoring mechanism identified; regulatory record-keeping requirements likely unmet.",
        control=CONTROL_LIBRARY["audit_trail"],
        severity="Medium",
        matched_keywords=[],
    )


def _check_manual_process(text: str) -> Optional[AuditFinding]:
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
# Rules 6-10: New
# ---------------------------------------------------------------------------

def _check_data_security(text: str) -> Optional[AuditFinding]:
    """Detects absence of encryption or data protection controls."""
    security_keywords = [
        r"\bencrypt\w*\b", r"\bTLS\b", r"\bSSL\b", r"\bhash\w*\b",
        r"\bmask\w*\b", r"\bobfuscat\w*\b", r"\bsecure\b", r"\bAES\b",
    ]
    found = any(re.search(kw, text, re.IGNORECASE) for kw in security_keywords)
    if found:
        return None
    # Only flag if data-related terms are present
    data_terms = [r"\bdata\b", r"\brecord\b", r"\bcustomer\b", r"\bpersonal\b",
                  r"\bsensitive\b", r"\bconfidential\b", r"\bpayment\b", r"\bbank\b"]
    has_data = any(re.search(kw, text, re.IGNORECASE) for kw in data_terms)
    if not has_data:
        return None
    return AuditFinding(
        rule_id="SEC-001",
        risk="Data security risk — sensitive data may be stored or transmitted without encryption, exposing it to breach.",
        gap="No encryption, masking, or data protection mechanism mentioned for sensitive information handling.",
        control=CONTROL_LIBRARY["encryption"],
        severity="High",
        matched_keywords=[],
    )


def _check_access_control(text: str) -> Optional[AuditFinding]:
    """Detects absence of authentication or access control."""
    access_keywords = [
        r"\bpassword\b", r"\bMFA\b", r"\b2FA\b", r"\bauthenticat\w*\b",
        r"\bRBAC\b", r"\baccess control\b", r"\bpermission\w*\b",
        r"\brole.based\b", r"\blogin\b", r"\bcredential\w*\b",
    ]
    found = any(re.search(kw, text, re.IGNORECASE) for kw in access_keywords)
    if found:
        return None
    system_terms = [r"\bsystem\b", r"\bplatform\b", r"\bportal\b",
                    r"\bapplication\b", r"\bdatabase\b", r"\bserver\b"]
    has_system = any(re.search(kw, text, re.IGNORECASE) for kw in system_terms)
    if not has_system:
        return None
    return AuditFinding(
        rule_id="ACC-001",
        risk="Unauthorized access risk — no authentication or access control mechanism detected, enabling unrestricted system access.",
        gap="System or platform access controls not defined; no evidence of RBAC, MFA, or credential management.",
        control=CONTROL_LIBRARY["access"],
        severity="High",
        matched_keywords=[],
    )


def _check_missing_contracts(text: str) -> Optional[AuditFinding]:
    """Detects verbal or informal agreements without formal contracts."""
    informal_patterns = [
        r"\bverbally?\b", r"\binformal\w*\b", r"\bhandshake\b",
        r"\bno contract\b", r"\bno agreement\b", r"\bno SLA\b",
        r"\bno written\b", r"\bno formal\b",
    ]
    matched = [p for p in informal_patterns if re.search(p, text, re.IGNORECASE)]
    if not matched:
        return None
    return AuditFinding(
        rule_id="CNT-001",
        risk="Contractual risk — informal or verbal agreements create unenforceable obligations and dispute liability.",
        gap="No formal written contract, SLA, or agreement governing the process or third-party relationships.",
        control=CONTROL_LIBRARY["contract"],
        severity="Medium",
        matched_keywords=matched,
    )


def _check_missing_limits(text: str) -> Optional[AuditFinding]:
    """Detects absence of transaction limits or thresholds."""
    limit_keywords = [
        r"\blimit\w*\b", r"\bthreshold\w*\b", r"\bcap\b", r"\bceiling\b",
        r"\bmaximum\b", r"\bmin\w*\b", r"\bvelocity\b", r"\bquota\b",
    ]
    found = any(re.search(kw, text, re.IGNORECASE) for kw in limit_keywords)
    if found:
        return None
    financial_terms = [r"\btransaction\b", r"\bpayment\b", r"\btransfer\b",
                       r"\bwithdrawal\b", r"\bpurchase\b", r"\binvoice\b", r"\bsettle\w*\b"]
    has_financial = any(re.search(kw, text, re.IGNORECASE) for kw in financial_terms)
    if not has_financial:
        return None
    return AuditFinding(
        rule_id="LMT-001",
        risk="Exposure risk — no transaction limits or velocity controls allow uncapped financial outflows without detection.",
        gap="No thresholds, caps, or velocity limits defined for financial transactions, enabling excessive exposure.",
        control=CONTROL_LIBRARY["limits"],
        severity="Medium",
        matched_keywords=[],
    )


def _check_missing_testing(text: str) -> Optional[AuditFinding]:
    """Detects deployment or changes without testing controls."""
    testing_keywords = [
        r"\btest\w*\b", r"\bUAT\b", r"\bQA\b", r"\bquality assurance\b",
        r"\bregression\b", r"\bstaging\b", r"\bsandbox\b", r"\bvalidat\w*\b",
    ]
    found = any(re.search(kw, text, re.IGNORECASE) for kw in testing_keywords)
    if found:
        return None
    change_terms = [r"\bdeploy\w*\b", r"\brelease\w*\b", r"\bupdat\w*\b",
                    r"\bchange\b", r"\bmigrat\w*\b", r"\blaunch\w*\b"]
    has_change = any(re.search(kw, text, re.IGNORECASE) for kw in change_terms)
    if not has_change:
        return None
    return AuditFinding(
        rule_id="TST-001",
        risk="Change management risk — deployments without testing controls introduce defects and system instability into production.",
        gap="No UAT, regression testing, or QA gate identified before production deployment.",
        control=CONTROL_LIBRARY["testing"],
        severity="Medium",
        matched_keywords=[],
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
# Rule registry
# ---------------------------------------------------------------------------

RULES = [
    _check_segregation_of_duties,
    _check_missing_approval,
    _check_missing_audit_trail,
    _check_manual_process,
    _check_single_point_of_failure,
    _check_data_security,
    _check_access_control,
    _check_missing_contracts,
    _check_missing_limits,
    _check_missing_testing,
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_process(process: str) -> AuditResult:
    """Run all audit rules. Always completes — individual failures are skipped silently."""
    text = process.strip()
    findings = []
    for rule in RULES:
        try:
            finding = rule(text)
            if finding:
                findings.append(finding)
        except Exception:
            continue
    return AuditResult(
        findings=findings,
        risks=[f.risk for f in findings],
        gaps=[f.gap for f in findings],
        controls=list(dict.fromkeys(f.control for f in findings)),
        severity=_calculate_severity(findings),
        rule_count=len(findings),
    )


def format_for_llm(result: AuditResult) -> str:
    """Serialize rule-engine output for LLM enhancement prompt."""
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

