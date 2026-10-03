"""
Comprehensive Test Suite for Context-Aware Secret Leakage Detection.

Evaluates:
1. Shannon Entropy calculations
2. Placeholder/Documentation False-Positive filtering
3. Regex & Secret Pattern detection (AWS, Tokens, Passwords, etc.)
4. IaC Context Analysis (Terraform & CloudFormation)
5. AWS Resource Extraction (including sensitive resources like IAM, RDS, Lambda)
6. CI/CD Pipeline Context Detection (GitHub Actions)
7. Deterministic Explainable Risk Scoring Engine
8. Benchmark against expected results fixtures
"""

import os
import sys
import json
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from scanner.scanner import scan_content, scan_file, shannon_entropy, is_placeholder, redact
from scanner.iac_analyzer import analyze, analyze_file, detect_file_type
from scanner.risk_engine import assess_risk, scan_and_assess, format_report


# =============================================================================
# 1. ENTROPY & STRING ANALYSIS TESTS
# =============================================================================

def test_shannon_entropy_values():
    assert shannon_entropy("") == 0.0
    low_ent = shannon_entropy("aaaaaaaaaaaa")
    assert low_ent < 1.0, f"Expected low entropy (< 1.0), got {low_ent}"
    
    high_ent = shannon_entropy("8fA#k9$mZ2!vL1@xQ")
    assert high_ent > 3.5, f"Expected high entropy (> 3.5), got {high_ent}"


def test_placeholder_patterns():
    # Common placeholders that must be recognized
    assert is_placeholder("REPLACE_ME")
    assert is_placeholder("YOUR_API_KEY_HERE")
    assert is_placeholder("CHANGE_ME_NOW")
    assert is_placeholder("AKIAIOSFODNN7EXAMPLE")
    assert is_placeholder("${{ secrets.MY_SECRET }}")
    assert is_placeholder("var.db_password")
    assert is_placeholder("<INSERT_TOKEN>")
    
    # Real-looking synthetic values must NOT be recognized as placeholders
    assert not is_placeholder("AKIA1234567890FAKEEX")
    assert not is_placeholder("ghp_1234567890abcdefghijklmnopqrstuvwxyz")


def test_redaction_helper():
    val = "AKIA1234567890FAKEEX"
    redacted = redact(val, show=4)
    assert redacted.startswith("AKIA")
    assert redacted.endswith("KEEX")
    assert "*" in redacted
    assert "1234567890FA" not in redacted


# =============================================================================
# 2. SECRET SCANNER DETECTION TESTS
# =============================================================================

def test_aws_access_key_detection():
    content = 'aws_key = "AKIA1234567890FAKEEX"'
    findings = scan_content(content, "test.py")
    assert len(findings) == 1
    assert findings[0].secret_type == "aws_access_key"
    assert findings[0].matched_value == "AKIA1234567890FAKEEX"
    assert findings[0].is_placeholder is False


def test_github_token_detection():
    content = 'gh_token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz12"'
    findings = scan_content(content, "auth.py")
    assert len(findings) >= 1
    assert any(f.secret_type == "github_token" for f in findings)


def test_clean_file_no_findings():
    content = '''
def add(a, b):
    return a + b
    '''
    findings = scan_content(content, "clean.py")
    assert len(findings) == 0


# =============================================================================
# 3. IaC & RESOURCE ANALYSIS TESTS
# =============================================================================

def test_terraform_iac_and_resource_extraction():
    content = '''
provider "aws" { region = "us-east-1" }
resource "aws_instance" "web" { ami = "ami-1234" }
resource "aws_iam_role" "admin" { name = "admin_role" }
    '''
    ctx = analyze("infrastructure/main.tf", content)
    assert ctx.file_type == "terraform"
    assert ctx.iac_type == "terraform"
    assert ctx.cloud_provider == "aws"
    assert "aws_instance" in ctx.aws_resources
    assert "aws_iam_role" in ctx.aws_resources
    assert ctx.ci_cd_context is False


def test_cloudformation_iac_and_resource_extraction():
    content = '''
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  MyDb:
    Type: AWS::RDS::DBInstance
    '''
    ctx = analyze("cloudformation/db.yaml", content)
    assert ctx.file_type == "cloudformation"
    assert ctx.iac_type == "cloudformation"
    assert "AWS::RDS::DBInstance" in ctx.aws_resources


def test_github_actions_workflow_detection():
    content = '''
name: Deploy
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
    '''
    ctx = analyze(".github/workflows/deploy.yml", content)
    assert ctx.file_type == "github_actions"
    assert ctx.ci_cd_context is True
    assert ctx.ci_cd_platform == "github_actions"


# =============================================================================
# 4. CONTEXT-AWARE RISK SCORING TESTS
# =============================================================================

def test_terraform_secret_yields_critical():
    content = '''
resource "aws_instance" "web" {
  access_key = "AKIA1234567890FAKEEX"
}
    '''
    findings = scan_content(content, "infra/main.tf")
    ctx = analyze("infra/main.tf", content)
    assessment = assess_risk("infra/main.tf", findings, ctx)
    
    assert assessment.risk_level == "CRITICAL"
    assert assessment.risk_score >= 80
    assert any(f.name == "terraform_context" for f in assessment.factors)
    assert any(f.name == "aws_resource_detected" for f in assessment.factors)


def test_github_actions_secret_yields_critical():
    content = '''
name: Deploy
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    env:
      AWS_ACCESS_KEY_ID: "AKIA9876543210AWSKEY"
    '''
    findings = scan_content(content, ".github/workflows/deploy.yml")
    ctx = analyze(".github/workflows/deploy.yml", content)
    assessment = assess_risk(".github/workflows/deploy.yml", findings, ctx)
    
    assert assessment.risk_level == "CRITICAL"
    assert assessment.risk_score >= 80
    assert any(f.name == "cicd_context" for f in assessment.factors)


def test_documentation_placeholder_yields_safe():
    content = '''
# Example Configuration
export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
export API_KEY="YOUR_API_KEY_HERE"
    '''
    findings = scan_content(content, "docs/README.md")
    ctx = analyze("docs/README.md", content)
    assessment = assess_risk("docs/README.md", findings, ctx)
    
    assert assessment.risk_level in ("SAFE", "LOW")
    assert assessment.risk_score < 40


# =============================================================================
# 5. FIXTURE BENCHMARK TESTS
# =============================================================================

def test_fixtures_against_expected_results():
    expected_path = PROJECT_ROOT / "tests" / "expected" / "expected_results.json"
    with open(expected_path, "r", encoding="utf-8") as f:
        expected_items = json.load(f)
        
    for item in expected_items:
        fixture_file = PROJECT_ROOT / item["file"]
        assert fixture_file.exists(), f"Fixture file {fixture_file} does not exist"
        
        assessment = scan_and_assess(str(fixture_file))
        assert assessment.risk_level == item["expected_risk_level"], (
            f"Fixture {item['file']}: expected risk {item['expected_risk_level']}, "
            f"got {assessment.risk_level} (score: {assessment.risk_score})"
        )
        
        if "expected_iac" in item:
            assert assessment.iac_type == item["expected_iac"]
            
        if "expected_resources" in item:
            for r in item["expected_resources"]:
                assert r in assessment.aws_resources


# =============================================================================
# RUN ALL DIRECTLY IF INVOKED AS SCRIPT
# =============================================================================

if __name__ == "__main__":
    tests = [
        test_shannon_entropy_values,
        test_placeholder_patterns,
        test_redaction_helper,
        test_aws_access_key_detection,
        test_github_token_detection,
        test_clean_file_no_findings,
        test_terraform_iac_and_resource_extraction,
        test_cloudformation_iac_and_resource_extraction,
        test_github_actions_workflow_detection,
        test_terraform_secret_yields_critical,
        test_github_actions_secret_yields_critical,
        test_documentation_placeholder_yields_safe,
        test_fixtures_against_expected_results,
    ]
    
    passed = 0
    failed = 0
    print("=" * 64)
    print("  RUNNING CONTEXT-AWARE SECRET DETECTOR TESTS")
    print("=" * 64)
    for t in tests:
        try:
            t()
            print(f"  [PASS] {t.__name__}")
            passed += 1
        except Exception as e:
            print(f"  [FAIL] {t.__name__} -> {e}")
            failed += 1
            
    print("=" * 64)
    print(f"  RESULTS: {passed} PASSED, {failed} FAILED")
    print("=" * 64)
    sys.exit(1 if failed > 0 else 0)
