"""Report format tests."""

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from scanner.cli import generate_sarif_report
from scanner.risk_engine import RiskAssessment
from scanner.scanner import SecretFinding


def test_sarif_contains_findings_without_secret_values(tmp_path):
    finding = SecretFinding(
        secret_type="api_key",
        matched_value="DO_NOT_SERIALIZE",
        line_number=7,
        line_content="api_key = DO_NOT_SERIALIZE",
        entropy=4.2,
        confidence=0.9,
        is_placeholder=False,
    )
    assessment = RiskAssessment(
        filepath="src/app.py",
        file_type="python",
        iac_type="none",
        cloud_provider="none",
        aws_resources=[],
        ci_cd_context=False,
        ci_cd_platform="none",
        findings=[finding],
        risk_level="HIGH",
        risk_score=75,
        factors=[],
        explanation="redacted",
    )
    output = tmp_path / "report.sarif"
    generate_sarif_report([assessment], str(output))
    report = json.loads(output.read_text())
    result = report["runs"][0]["results"][0]
    serialized = output.read_text()
    assert result["ruleId"] == "secret/api_key"
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 7
    assert "DO_NOT_SERIALIZE" not in serialized


if __name__ == "__main__":
    test_sarif_contains_findings_without_secret_values(Path("/tmp"))
    print("[PASS] test_sarif_contains_findings_without_secret_values")