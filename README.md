# Context-Aware Secret Leakage Detection for Cloud CI/CD & Infrastructure-as-Code (IaC)

[![CI Security Scan](https://github.com/security/secret-leakage-detector/actions/workflows/security-scan.yml/badge.svg)](https://github.com/security/secret-leakage-detector)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## 1. Project Title & Abstract

**Project Title:** Context-Aware Secret Leakage Detection for Cloud CI/CD and Infrastructure-as-Code (IaC)  
**Authors:** Academic 2-Day Security Engineering MVP  
**Focus:** Cloud Security, Infrastructure-as-Code (Terraform / CloudFormation), CI/CD (GitHub Actions), Entropy Analysis, Explainable Risk Scoring.

### Abstract
Traditional secret detection tools (e.g., standard regex scanners) primarily operate in a binary mode: a secret is either found or not found. They treat a leaked credential in a sample `README.md` the exact same way as a hardcoded root access key embedded inside a production Terraform IAM definition or a GitHub Actions deployment workflow. 

This project introduces **Context-Aware Secret Leakage Detection**, a deterministic, explainable security analysis engine that enriches raw pattern-matching and Shannon entropy with structural context (IaC status, AWS resource categorization, CI/CD execution context, and path semantics) to generate **calibrated, human-explainable risk scores (0–100)** mapped into 5 standardized severity levels: `SAFE`, `LOW`, `MEDIUM`, `HIGH`, and `CRITICAL`.

---

## 2. Problem Statement & Motivation

### The Challenge of Modern Cloud Secret Sprawl
In modern GitOps and Cloud DevOps architectures:
- Cloud infrastructure is provisioned declaratively via **Terraform** or **CloudFormation**.
- Continuous Integration & Deployment (CI/CD) pipelines have direct access to high-privilege cloud roles.
- Secrets committed into IaC templates or CI/CD pipelines pose immediate, automated risk of cloud infrastructure compromise.

### Limitations of Pattern-Only Detection
| Limitation | Traditional Regex Scanners | Our Context-Aware Approach |
| :--- | :--- | :--- |
| **Context Blindness** | Treats `README.md` key same as `deploy.tf` key. | Differentiates documentation vs. live deployment contexts. |
| **High False Positives** | Flags `AKIAIOSFODNN7EXAMPLE` or `${{ secrets.KEY }}`. | Filters documentation examples and valid secret expressions. |
| **No Resource Impact** | Does not identify which cloud resource is exposed. | Detects whether the secret attaches to an `aws_iam_role`, `aws_instance`, or `AWS::RDS::DBInstance`. |
| **Black-box Scoring** | Binary output or opaque heuristics. | Transparent, additive scoring with configurable YAML weights. |

---

## 3. Core Architecture & Novelty

### System Architecture
```
                         Target File / Directory
                                   │
                                   ▼
                       ┌────────────────────────┐
                       │ File Type & Path Parser│
                       └───────────┬────────────┘
                                   │
                 ┌─────────────────┴─────────────────┐
                 ▼                                   ▼
     ┌──────────────────────┐            ┌──────────────────────┐
     │ Secret Match Engine  │            │ IaC Context Analyzer │
     │  • Regex Patterns    │            │  • Terraform Parser  │
     │  • Shannon Entropy   │            │  • CloudFormation    │
     │  • Placeholder Check │            │  • AWS Resource Extr.│
     │  • Redaction Filter  │            │  • CI/CD Workflow    │
     └───────────┬──────────┘            └───────────┬──────────┘
                 │                                   │
                 └─────────────────┬─────────────────┘
                                   │
                                   ▼
                   ┌───────────────────────────────┐
                   │  Context-Aware Risk Engine    │
                   │  (Configurable YAML Weights)  │
                   │   • Additive Scoring (0-100)  │
                   │   • Factor Attribution        │
                   └───────────────┬───────────────┘
                                   │
                                   ▼
        ┌─────────────────────────────────────────────────────┐
        │                 Multimodal Output                   │
        │  • Terminal CLI Summary  • JSON Security Report     │
        │  • Interactive HTML Report • Streamlit UI Dashboard │
        │  • GitHub Actions CI Security Gate (Exit Code 0/1)  │
        └─────────────────────────────────────────────────────┘
```

---

## 4. Context-Aware Risk Scoring Model

The risk engine computes an additive composite score $S \in [0, 100]$ based on deterministic weights configured in [`config/risk_rules.yaml`](file:///c:/Study/404/my/config/risk_rules.yaml):

$$\text{Risk Score} = \min\left(100, \max\left(0, \sum \text{Positive Factors} - \sum \text{Reductions}\right)\right)$$

### Scoring Breakdown
| Category | Factor Name | Points | Condition |
| :--- | :--- | :---: | :--- |
| **Base** | `secret_detected` | **+40** | High-confidence secret pattern found |
| **Entropy** | `high_entropy` | **+15** | Shannon Entropy $H(X) > 4.0$ |
| **IaC Context** | `terraform_context` | **+10** | File is Terraform (`.tf`) |
| **IaC Context** | `cloudformation_context`| **+10** | File is CloudFormation (`AWSTemplateFormatVersion`) |
| **Cloud Asset** | `aws_resource_detected` | **+10** | Associated with an AWS resource |
| **Cloud Asset** | `sensitive_aws_resource`| **+5** | Sensitive resource (`aws_iam_role`, `aws_kms_key`, etc.) |
| **CI/CD** | `cicd_context` | **+20** | Defined in `.github/workflows/` |
| **Environment** | `production_context` | **+15** | File path matches `prod`, `deploy`, `infra` |
| **Credential** | `aws_credential_type` | **+5** | AWS Access / Secret Key format |
| *Reduction* | `placeholder_value` | **-30** | Value matches known placeholder/sample |
| *Reduction* | `test_example_file` | **-20** | Path contains `test`, `example`, `docs` |
| *Reduction* | `low_entropy` | **-10** | Shannon Entropy $H(X) < 2.5$ |

### Severity Scale
- **`0 – 19`** : `SAFE`
- **`20 – 39`** : `LOW`
- **`40 – 59`** : `MEDIUM`
- **`60 – 79`** : `HIGH`
- **`80 – 100`** : `CRITICAL`

---

## 5. Project Directory Structure

```
secret-leakage-detector/
├── .github/
│   └── workflows/
│       └── security-scan.yml         # GitHub Actions CI Security Gate
├── config/
│   └── risk_rules.yaml               # Configurable Scoring Rules & Thresholds
├── dashboard/
│   └── app.py                        # Streamlit Visual Analytics Dashboard
├── reports/
│   ├── scan_report.json              # Structured JSON Output
│   └── scan_report.html              # Standalone Visual HTML Report
├── scanner/
│   ├── __init__.py
│   ├── scanner.py                    # Regex & Entropy Matcher + Redaction
│   ├── iac_analyzer.py               # Terraform, CFN, AWS Resource & CI/CD Parser
│   ├── risk_engine.py                # Deterministic Explainability Engine
│   └── cli.py                        # CLI Runner & Report Generators
├── tests/
│   ├── fixtures/                     # Test Corpus (Clean, Terraform, CI/CD, Docs)
│   │   ├── clean/
│   │   ├── terraform/
│   │   ├── cloudformation/
│   │   ├── github_actions/
│   │   └── docs/
│   ├── expected/
│   │   └── expected_results.json     # Ground Truth Validation Spec
│   └── test_all.py                   # Automated Test Suite
├── requirements.txt                  # Lightweight Dependencies
└── README.md                         # Academic Documentation
```

---

## 6. Installation & Quickstart

### Prerequisites
- Python 3.10+
- Free / Open Source tools only (No paid APIs or cloud accounts required)

### Setup
```bash
# 1. Clone repository
git clone https://github.com/security/secret-leakage-detector.git
cd secret-leakage-detector

# 2. Create and activate virtual environment
python -m venv venv
# On Windows:
.\venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt
```

---

## 7. Usage Guide

### 1. Run Automated Unit & Benchmark Tests
```bash
python tests/test_all.py
```

### 2. Scan a Project or Directory via CLI
```bash
# Scan the fixtures directory and export JSON & HTML reports
python scanner/cli.py ./tests/fixtures --json reports/scan_report.json --html reports/scan_report.html
```

#### Example Terminal Output
```
================================================================
  CONTEXT-AWARE SECRET LEAKAGE SCANNER
================================================================
  Target:            C:\Study\404\my\tests\fixtures
  Files Scanned:     7
  Secrets Detected:  3
----------------------------------------------------------------
  RISK DISTRIBUTION:
    SAFE:       4
    LOW:        0
    MEDIUM:     0
    HIGH:       0
    CRITICAL:   3
================================================================

🚨 CRITICAL & HIGH FINDINGS:

  [1] File:       tests\fixtures\terraform\deploy.tf
      Risk:       85/100 [CRITICAL]
      IaC:        Terraform (AWS Resource: aws_instance, aws_iam_role)
      CI/CD:      False (none)
      Reason:     CRITICAL: aws_access_key detected inside Terraform IaC, near AWS resource(s) aws_iam_role, aws_instance, targeting AWS.
      Factors:
        + 40 Secret type(s) detected: aws_access_key
        + 15 High entropy (4.06) suggests a real secret
        + 10 File is Terraform Infrastructure-as-Code
        + 10 AWS resource(s): aws_instance, aws_iam_role
        +  5 Sensitive resource(s): aws_iam_role
        +  5 AWS credential detected — higher severity

  [2] File:       tests\fixtures\github_actions\deploy.yml
      Risk:       90/100 [CRITICAL]
      IaC:        None (AWS Resource: none)
      CI/CD:      True (github_actions)
      Reason:     CRITICAL: aws_access_key, aws_secret_key within a github_actions CI/CD pipeline, targeting AWS.
      Factors:
        + 40 Secret type(s) detected: aws_access_key, aws_secret_key
        + 15 High entropy (4.81) suggests a real secret
        + 20 File is part of a CI/CD pipeline (github_actions)
        + 15 File path references production/deployment context
        +  5 AWS credential detected — higher severity
```

### 3. Launch Interactive Streamlit Dashboard
```bash
streamlit run dashboard/app.py
```
The dashboard provides:
- Executive Risk Distribution charts
- Infrastructure-as-Code asset explorer
- Deep-dive factor breakdown table per file

---

## 8. CI/CD Integration (GitHub Actions)

The repository includes a production-ready workflow in [`.github/workflows/security-scan.yml`](file:///c:/Study/404/my/.github/workflows/security-scan.yml).
When triggered on `push` or `pull_request`:
1. Executes `tests/test_all.py`.
2. Runs `scanner/cli.py` with `--fail-on HIGH`.
3. If any `HIGH` or `CRITICAL` findings exist, the pipeline **fails the build** and blocks pull request merging.
4. Generates and uploads `reports/scan_report.html` and `reports/scan_report.json` as build artifacts.

---

## 9. Safety & Ethics Statement

- **100% Synthetic Data:** All test cases and fixtures utilize strictly synthetic, non-functional fake credentials (e.g., `AKIA1234567890FAKEEX`).
- **Zero Exploitation:** The scanner never connects to AWS endpoints or attempts authentication.
- **Redaction by Design:** Real secret values are never printed in plain text in CLI logs, JSON, or HTML reports.

---

## 10. Limitations & Future Work

1. **AST-based HCL Parsing:** Current version uses regex-assisted grammar tokenization; future versions could integrate `tree-sitter-hcl` for deeper AST traversal.
2. **Multi-Cloud Expansion:** Extend native resource sensitivity mappings to Azure Bicep/ARM and Google Cloud Deployment Manager.
3. **Cross-File Variable Resolution:** Trace Terraform `var.db_password` assignments across module boundaries.

---
*Created for Academic Demonstration — Context-Aware Cloud Security & IaC Verification.*
