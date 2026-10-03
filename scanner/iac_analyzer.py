"""
IaC Context Analyzer — detects Infrastructure-as-Code context and AWS resources.

Capabilities:
  1. File-type detection  (Terraform / CloudFormation / GitHub Actions / generic)
  2. AWS resource extraction  (from Terraform `resource` blocks and CFN `Type:`)
  3. CI/CD context detection  (GitHub Actions, Jenkins, GitLab CI markers)
  4. Cloud provider detection
"""

import re
import os
from dataclasses import dataclass


@dataclass
class IaCContext:
    """Context extracted from a file."""
    file_type: str              # terraform | cloudformation | github_actions | python | yaml | json | env | unknown
    iac_type: str               # terraform | cloudformation | none
    cloud_provider: str         # aws | azure | gcp | none
    aws_resources: list[str]    # e.g. ["aws_instance", "aws_s3_bucket"]
    ci_cd_context: bool         # True if file is CI/CD related
    ci_cd_platform: str         # github_actions | jenkins | gitlab_ci | none


# ---------------------------------------------------------------------------
# File-type detection
# ---------------------------------------------------------------------------

def detect_file_type(filepath: str, content: str) -> str:
    """Determine the file type from path and content."""
    name = os.path.basename(filepath).lower()
    ext = os.path.splitext(name)[1]
    dirparts = filepath.replace("\\", "/").lower()

    # GitHub Actions workflows
    if ".github/workflows" in dirparts or ".github\\workflows" in dirparts:
        return "github_actions"

    # Terraform
    if ext == ".tf":
        return "terraform"

    # CloudFormation — YAML/JSON with AWSTemplateFormatVersion
    if ext in (".yaml", ".yml", ".json"):
        if "AWSTemplateFormatVersion" in content or "aws::" in content.lower():
            return "cloudformation"

    # CI markers
    if name in ("jenkinsfile",):
        return "jenkins"
    if name == ".gitlab-ci.yml":
        return "gitlab_ci"

    # Generic
    if ext == ".py":
        return "python"
    if ext in (".yaml", ".yml"):
        return "yaml"
    if ext == ".json":
        return "json"
    if ext == ".env" or name.startswith(".env"):
        return "env"

    return "unknown"


# ---------------------------------------------------------------------------
# IaC detection
# ---------------------------------------------------------------------------

def detect_iac_type(file_type: str, content: str) -> str:
    """Classify Infrastructure-as-Code type."""
    if file_type == "terraform":
        return "terraform"
    if file_type == "cloudformation":
        return "cloudformation"
    # Heuristic: HCL-style blocks in non-.tf files
    if re.search(r'resource\s+"aws_', content):
        return "terraform"
    if "AWSTemplateFormatVersion" in content:
        return "cloudformation"
    return "none"


# ---------------------------------------------------------------------------
# AWS resource extraction
# ---------------------------------------------------------------------------

_TF_RESOURCE_RE = re.compile(r'resource\s+"(aws_\w+)"')
_CFN_RESOURCE_RE = re.compile(r'Type:\s*(AWS::[A-Za-z0-9:]+)')
_CFN_RESOURCE_JSON_RE = re.compile(r'"Type"\s*:\s*"(AWS::[A-Za-z0-9:]+)"')


def extract_aws_resources(content: str, iac_type: str) -> list[str]:
    """Extract AWS resource types from file content."""
    resources: list[str] = []
    if iac_type == "terraform":
        resources = _TF_RESOURCE_RE.findall(content)
    elif iac_type == "cloudformation":
        resources = _CFN_RESOURCE_RE.findall(content)
        resources += _CFN_RESOURCE_JSON_RE.findall(content)
    return list(set(resources))


# ---------------------------------------------------------------------------
# Cloud provider detection
# ---------------------------------------------------------------------------

def detect_cloud_provider(content: str, aws_resources: list[str]) -> str:
    """Detect which cloud provider the file references."""
    content_lower = content.lower()
    if aws_resources or "aws" in content_lower or "amazon" in content_lower:
        return "aws"
    if "azure" in content_lower or "microsoft.compute" in content_lower:
        return "azure"
    if "google" in content_lower or "gcp" in content_lower:
        return "gcp"
    return "none"


# ---------------------------------------------------------------------------
# CI/CD detection
# ---------------------------------------------------------------------------

_CICD_MARKERS = {
    "github_actions": [
        re.compile(r'^name:\s+', re.MULTILINE),
        re.compile(r'runs-on:', re.MULTILINE),
        re.compile(r'uses:\s+actions/', re.MULTILINE),
    ],
    "jenkins": [
        re.compile(r'pipeline\s*\{', re.MULTILINE),
        re.compile(r'stage\s*\(', re.MULTILINE),
    ],
    "gitlab_ci": [
        re.compile(r'stages:', re.MULTILINE),
        re.compile(r'script:', re.MULTILINE),
    ],
}


def detect_cicd_context(file_type: str, content: str) -> tuple[bool, str]:
    """Return (is_cicd, platform)."""
    if file_type in ("github_actions",):
        return True, "github_actions"
    if file_type == "jenkins":
        return True, "jenkins"
    if file_type == "gitlab_ci":
        return True, "gitlab_ci"

    # Heuristic scan
    for platform, patterns in _CICD_MARKERS.items():
        matches = sum(1 for p in patterns if p.search(content))
        if matches >= 2:
            return True, platform

    return False, "none"


# ---------------------------------------------------------------------------
# Main analysis function
# ---------------------------------------------------------------------------

def analyze(filepath: str, content: str) -> IaCContext:
    """
    Perform full context analysis on a file.

    Returns an IaCContext dataclass with all extracted context.
    """
    file_type = detect_file_type(filepath, content)
    iac_type = detect_iac_type(file_type, content)
    aws_resources = extract_aws_resources(content, iac_type)
    cloud_provider = detect_cloud_provider(content, aws_resources)
    is_cicd, cicd_platform = detect_cicd_context(file_type, content)

    return IaCContext(
        file_type=file_type,
        iac_type=iac_type,
        cloud_provider=cloud_provider,
        aws_resources=aws_resources,
        ci_cd_context=is_cicd,
        ci_cd_platform=cicd_platform,
    )


def analyze_file(filepath: str) -> IaCContext:
    """Convenience wrapper — read file and analyze."""
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()
    return analyze(filepath, content)
