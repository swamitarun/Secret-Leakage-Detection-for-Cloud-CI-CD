"""
Context-Aware Risk Engine — deterministic, explainable, additive scoring.

The key novelty: risk is NOT just "is there a regex match?" — it considers
WHERE the secret appears (IaC? CI/CD? which AWS resource? production path?)
and produces a transparent, human-readable breakdown.

Risk Score:  0–100  (additive, clamped)
Risk Levels: SAFE / LOW / MEDIUM / HIGH / CRITICAL

All weights are loaded from config/risk_rules.yaml and can be tuned without
touching code.
"""

import os
import yaml
from dataclasses import dataclass, field
from scanner.scanner import SecretFinding, redact
from scanner.iac_analyzer import IaCContext


# ---------------------------------------------------------------------------
# Load configurable weights
# ---------------------------------------------------------------------------

_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "config", "risk_rules.yaml")


def _load_config() -> dict:
    """Load risk scoring configuration from YAML."""
    with open(_CONFIG_PATH, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class RiskFactor:
    """A single factor that contributed to the risk score."""
    name: str
    points: int        # positive = risk increase, negative = risk decrease
    description: str


@dataclass
class RiskAssessment:
    """Complete risk assessment for a single file."""
    filepath: str
    file_type: str
    iac_type: str
    cloud_provider: str
    aws_resources: list[str]
    ci_cd_context: bool
    ci_cd_platform: str
    findings: list[SecretFinding]
    risk_level: str             # SAFE | LOW | MEDIUM | HIGH | CRITICAL
    risk_score: int             # 0–100
    factors: list[RiskFactor]   # transparent breakdown
    explanation: str            # one-line summary
    transformer_available: bool = False
    transformer_probability: float = 0.0
    transformer_confidence: float = 0.0
    hybrid_decision: str = "rules_only"


def _score_to_level(score: int, cfg: dict) -> str:
    """Map a 0-100 score to a risk level using config thresholds."""
    t = cfg["thresholds"]
    if score <= t["safe_max"]:
        return "SAFE"
    if score <= t["low_max"]:
        return "LOW"
    if score <= t["medium_max"]:
        return "MEDIUM"
    if score <= t["high_max"]:
        return "HIGH"
    return "CRITICAL"


def _is_test_path(filepath: str, keywords: list[str]) -> bool:
    """Check if the filepath looks like a test / example / docs file."""
    parts = filepath.replace("\\", "/").lower()
    return any(kw in parts for kw in keywords)


def _is_production_path(filepath: str, keywords: list[str]) -> bool:
    """Check if the filepath looks like a production / deployment file."""
    parts = filepath.replace("\\", "/").lower()
    return any(kw in parts for kw in keywords)


# ---------------------------------------------------------------------------
# Main scoring function
# ---------------------------------------------------------------------------

def assess_risk(
    filepath: str,
    findings: list[SecretFinding],
    context: IaCContext,
) -> RiskAssessment:
    """
    Compute a context-aware risk score from scanner findings + IaC context.

    The score is built additively from configurable factors:
      +40  secret_detected      (base, when any non-placeholder secret found)
      +15  high_entropy         (matched value entropy > 4.0)
      +10  terraform_context    (file is Terraform IaC)
      +10  cloudformation_context
      +10  aws_resource_detected
       +5  sensitive_aws_resource
      +20  cicd_context         (file is CI/CD pipeline)
      +15  production_context   (path references prod/deploy)
       +5  aws_credential_type
      -30  placeholder_value
      -20  test_example_file
      -10  low_entropy
       -5  low_confidence
    """
    cfg = _load_config()
    f_cfg = cfg["factors"]
    r_cfg = cfg["reductions"]
    factors: list[RiskFactor] = []
    score = 0

    # Separate real vs placeholder findings
    real_findings = [f for f in findings if not f.is_placeholder]
    placeholder_findings = [f for f in findings if f.is_placeholder]
    has_real = len(real_findings) > 0

    # ── 1. Secret detected ──────────────────────────────────────────────
    if has_real:
        pts = f_cfg["secret_detected"]
        secret_types = sorted({f.secret_type for f in real_findings})
        score += pts
        factors.append(RiskFactor(
            "secret_detected", pts,
            f"Secret type(s) detected: {', '.join(secret_types)}"
        ))
    elif placeholder_findings:
        pts = r_cfg["placeholder_value"]
        score += max(0, f_cfg["secret_detected"] + pts)  # base + reduction, floor 0
        factors.append(RiskFactor(
            "placeholder_only", pts,
            "Only placeholder/example values detected"
        ))
    else:
        # No findings at all
        return RiskAssessment(
            filepath=filepath,
            file_type=context.file_type,
            iac_type=context.iac_type,
            cloud_provider=context.cloud_provider,
            aws_resources=context.aws_resources,
            ci_cd_context=context.ci_cd_context,
            ci_cd_platform=context.ci_cd_platform,
            findings=findings,
            risk_level="SAFE",
            risk_score=0,
            factors=[RiskFactor("no_secret", 0, "No secrets detected")],
            explanation="No secrets detected.",
        )

    # ── 2. Entropy analysis ─────────────────────────────────────────────
    if has_real:
        max_ent = max(f.entropy for f in real_findings)
        if max_ent >= 3.5:
            pts = f_cfg["high_entropy"]
            score += pts
            factors.append(RiskFactor(
                "high_entropy", pts,
                f"High entropy ({max_ent:.2f}) suggests a real secret"
            ))
        elif max_ent < 2.5:
            pts = r_cfg["low_entropy"]
            score += pts
            factors.append(RiskFactor(
                "low_entropy", pts,
                f"Low entropy ({max_ent:.2f}) - may be a false positive"
            ))

    # ── 3. Low confidence reduction ─────────────────────────────────────
    if has_real:
        max_conf = max(f.confidence for f in real_findings)
        if max_conf < 0.5:
            pts = r_cfg["low_confidence"]
            score += pts
            factors.append(RiskFactor(
                "low_confidence", pts,
                f"Low pattern confidence ({max_conf:.2f})"
            ))

    # ── 4. IaC context ──────────────────────────────────────────────────
    if context.iac_type == "terraform":
        pts = f_cfg["terraform_context"]
        score += pts
        factors.append(RiskFactor(
            "terraform_context", pts,
            "File is Terraform Infrastructure-as-Code"
        ))
    elif context.iac_type == "cloudformation":
        pts = f_cfg["cloudformation_context"]
        score += pts
        factors.append(RiskFactor(
            "cloudformation_context", pts,
            "File is CloudFormation Infrastructure-as-Code"
        ))

    # ── 5. AWS resource detected ────────────────────────────────────────
    if context.aws_resources:
        pts = f_cfg["aws_resource_detected"]
        score += pts
        factors.append(RiskFactor(
            "aws_resource_detected", pts,
            f"AWS resource(s): {', '.join(context.aws_resources)}"
        ))

        # Extra points for sensitive resources
        sensitive_set = set(cfg.get("sensitive_aws_resources", []))
        sensitive_found = set(context.aws_resources) & sensitive_set
        if sensitive_found:
            pts2 = f_cfg["sensitive_aws_resource"]
            score += pts2
            factors.append(RiskFactor(
                "sensitive_aws_resource", pts2,
                f"Sensitive resource(s): {', '.join(sorted(sensitive_found))}"
            ))

    # ── 6. CI/CD context ────────────────────────────────────────────────
    if context.ci_cd_context:
        pts = f_cfg["cicd_context"]
        score += pts
        factors.append(RiskFactor(
            "cicd_context", pts,
            f"File is part of a CI/CD pipeline ({context.ci_cd_platform})"
        ))

    # ── 7. Production / deployment path ─────────────────────────────────
    prod_kws = cfg.get("production_path_keywords", [])
    if _is_production_path(filepath, prod_kws):
        pts = f_cfg["production_context"]
        score += pts
        factors.append(RiskFactor(
            "production_context", pts,
            "File path references production/deployment context"
        ))

    # ── 8. AWS credential type bonus ────────────────────────────────────
    if has_real:
        aws_types = {"aws_access_key", "aws_secret_key"}
        if any(f.secret_type in aws_types for f in real_findings):
            pts = f_cfg["aws_credential_type"]
            score += pts
            factors.append(RiskFactor(
                "aws_credential_type", pts,
                "AWS credential detected - higher severity"
            ))

    # ── 9. Placeholder reduction ────────────────────────────────────────
    if placeholder_findings and has_real:
        pass

    # ── 10. Test / example file path reduction ──────────────────────────
    test_kws = cfg.get("test_path_keywords", [])
    if _is_test_path(filepath, test_kws) and not _is_production_path(filepath, prod_kws):
        pts = r_cfg["test_example_file"]
        score += pts
        factors.append(RiskFactor(
            "test_example_file", pts,
            "File path indicates test/example/documentation context"
        ))

    # ── Clamp and map ───────────────────────────────────────────────────
    score = max(0, min(100, score))
    level = _score_to_level(score, cfg)

    # Build explanation
    explanation = _build_explanation(level, context, real_findings)

    return RiskAssessment(
        filepath=filepath,
        file_type=context.file_type,
        iac_type=context.iac_type,
        cloud_provider=context.cloud_provider,
        aws_resources=context.aws_resources,
        ci_cd_context=context.ci_cd_context,
        ci_cd_platform=context.ci_cd_platform,
        findings=findings,
        risk_level=level,
        risk_score=score,
        factors=factors,
        explanation=explanation,
    )


def _build_explanation(level: str, ctx: IaCContext, real: list[SecretFinding]) -> str:
    """Generate a one-line human explanation."""
    if not real:
        return "No real secrets detected."

    types = sorted({f.secret_type for f in real})
    parts = []

    if ctx.iac_type != "none":
        parts.append(f"detected inside {ctx.iac_type.capitalize()} IaC")
    if ctx.ci_cd_context:
        parts.append(f"within a {ctx.ci_cd_platform} CI/CD pipeline")
    if ctx.aws_resources:
        parts.append(f"near AWS resource(s) {', '.join(ctx.aws_resources)}")
    if ctx.cloud_provider != "none":
        parts.append(f"targeting {ctx.cloud_provider.upper()}")

    type_str = ", ".join(types)
    context_str = ", ".join(parts) if parts else "in application code"
    return f"{level}: {type_str} {context_str}."


# ---------------------------------------------------------------------------
# Convenience wrappers
# ---------------------------------------------------------------------------

def scan_and_assess(filepath: str) -> RiskAssessment:
    """End-to-end: read file → scan → analyze context → assess risk."""
    from scanner.scanner import scan_file
    from scanner.iac_analyzer import analyze_file

    findings = scan_file(filepath)
    context = analyze_file(filepath)
    return assess_risk(filepath, findings, context)


# ---------------------------------------------------------------------------
# Reporting helpers
# ---------------------------------------------------------------------------

def format_report(assessment: RiskAssessment) -> str:
    """Format a RiskAssessment as a human-readable terminal report."""
    lines = [
        "=" * 64,
        "  SECRET SCAN REPORT",
        "=" * 64,
        f"  File:           {assessment.filepath}",
        f"  File Type:      {assessment.file_type}",
        f"  IaC:            {assessment.iac_type}",
        f"  Cloud Provider: {assessment.cloud_provider}",
        f"  AWS Resources:  {', '.join(assessment.aws_resources) or 'none'}",
        f"  CI/CD:          {assessment.ci_cd_context} ({assessment.ci_cd_platform})",
        f"  Risk Score:     {assessment.risk_score}/100",
        f"  Risk Level:     {assessment.risk_level}",
        "-" * 64,
    ]

    if assessment.findings:
        lines.append("  FINDINGS:")
        for i, f in enumerate(assessment.findings, 1):
            lines.append(f"    [{i}] Type:       {f.secret_type}")
            lines.append(f"        Line:       {f.line_number}")
            lines.append(f"        Entropy:    {f.entropy}")
            lines.append(f"        Confidence: {f.confidence}")
            lines.append(f"        Placeholder:{f.is_placeholder}")
    else:
        lines.append("  No secrets detected.")

    lines.append("-" * 64)
    lines.append("  SCORING BREAKDOWN:")
    for fac in assessment.factors:
        sign = "+" if fac.points >= 0 else ""
        lines.append(f"    {sign}{fac.points:3d}  {fac.description}")

    lines.append("-" * 64)
    lines.append(f"  EXPLANATION: {assessment.explanation}")
    lines.append("=" * 64)
    return "\n".join(lines)


def to_json_dict(assessment: RiskAssessment) -> dict:
    """Convert a RiskAssessment to a JSON-serialisable dict (no secret values)."""
    return {
        "file": assessment.filepath,
        "file_type": assessment.file_type,
        "iac_type": assessment.iac_type,
        "cloud_provider": assessment.cloud_provider,
        "aws_resources": assessment.aws_resources,
        "ci_cd_context": assessment.ci_cd_context,
        "ci_cd_platform": assessment.ci_cd_platform,
        "risk_score": assessment.risk_score,
        "risk_level": assessment.risk_level,
        "explanation": assessment.explanation,
        "transformer": {
            "available": assessment.transformer_available,
            "secret_probability": assessment.transformer_probability,
            "confidence": assessment.transformer_confidence,
            "hybrid_decision": assessment.hybrid_decision,
        },
        "findings": [
            {
                "secret_type": f.secret_type,
                "line": f.line_number,
                "entropy": f.entropy,
                "confidence": f.confidence,
                "is_placeholder": f.is_placeholder,
            }
            for f in assessment.findings
        ],
        "factors": [
            {"name": fac.name, "points": fac.points, "description": fac.description}
            for fac in assessment.factors
        ],
    }
