"""
Project-Specific Cloud IaC & CI/CD Security Benchmark Dataset Generator.
Generates 500+ diverse, synthetic, safe examples across Terraform, CloudFormation,
GitHub Actions, Jenkins, GitLab CI, and scripts for comprehensive benchmark evaluation.
"""

import os
import json
import random
import string
from pathlib import Path
from typing import List, Dict, Any


def _rand_alnum(k: int) -> str:
    return "".join(random.choices(string.ascii_letters + string.digits, k=k))


def _rand_hex(k: int) -> str:
    return "".join(random.choices("0123456789abcdef", k=k))


def _fake_aws_key() -> str:
    return f"AKIA{''.join(random.choices(string.ascii_uppercase + string.digits, k=16))}"


def _fake_secret_key() -> str:
    chars = string.ascii_letters + string.digits + "+/"
    return "".join(random.choices(chars, k=40))


def _fake_gh_token() -> str:
    return f"ghp_{_rand_alnum(36)}"


def generate_iac_benchmark(n_samples: int = 600, output_path: str = "dataset/iac_cicd_benchmark.json") -> List[Dict[str, Any]]:
    """Generate comprehensive IaC and CI/CD benchmark suite."""
    random.seed(1337)
    benchmark_items = []
    
    # 1. Terraform Real Secrets (Critical)
    tf_resources = ["aws_iam_role", "aws_db_instance", "aws_secretsmanager_secret", "aws_kms_key", "aws_instance", "aws_s3_bucket"]
    for i in range(100):
        res = random.choice(tf_resources)
        key_type = random.choice(["aws_access_key", "aws_secret_key", "password", "token"])
        if key_type == "aws_access_key":
            val = _fake_aws_key()
            line = f'  access_key = "{val}"'
        elif key_type == "aws_secret_key":
            val = _fake_secret_key()
            line = f'  secret_key = "{val}"'
        elif key_type == "password":
            val = f"DbPass_{_rand_alnum(12)}!"
            line = f'  password = "{val}"'
        else:
            val = _fake_gh_token()
            line = f'  token = "{val}"'
            
        text = f'''provider "aws" {{
  region = "us-east-1"
}}

resource "{res}" "primary" {{
{line}
  tags = {{
    Environment = "production"
    ManagedBy   = "terraform"
  }}
}}'''
        benchmark_items.append({
            "id": f"tf-sec-{i:04d}",
            "text": text,
            "value": val,
            "label": 1,
            "secret_type": key_type,
            "file_type": "terraform",
            "iac_type": "terraform",
            "cloud_provider": "aws",
            "aws_resource": res,
            "ci_cd_context": False,
            "is_placeholder": False,
            "expected_risk": "CRITICAL"
        })

    # 2. Terraform Clean / Variable References (Safe / Low)
    for i in range(100):
        res = random.choice(tf_resources)
        is_var = (i % 2 == 0)
        if is_var:
            text = f'''variable "db_password" {{
  type      = string
  sensitive = true
}}

resource "{res}" "db" {{
  password = var.db_password
  tags = {{
    Environment = "staging"
  }}
}}'''
        else:
            text = f'''resource "{res}" "cluster" {{
  allocated_storage = 20
  engine            = "postgres"
  tags = {{
    Project = "analytics"
  }}
}}'''
        benchmark_items.append({
            "id": f"tf-clean-{i:04d}",
            "text": text,
            "value": "",
            "label": 0,
            "secret_type": "none",
            "file_type": "terraform",
            "iac_type": "terraform",
            "cloud_provider": "aws",
            "aws_resource": res,
            "ci_cd_context": False,
            "is_placeholder": False,
            "expected_risk": "SAFE"
        })

    # 3. CloudFormation Real Secrets (Critical)
    cfn_resources = ["AWS::RDS::DBInstance", "AWS::IAM::User", "AWS::SecretsManager::Secret", "AWS::EC2::Instance"]
    for i in range(80):
        res = random.choice(cfn_resources)
        val = _fake_aws_key() if i % 2 == 0 else _fake_secret_key()
        prop = "AccessKeyId" if i % 2 == 0 else "SecretAccessKey"
        text = f'''AWSTemplateFormatVersion: '2010-09-09'
Description: Production Infrastructure
Resources:
  AppService:
    Type: {res}
    Properties:
      {prop}: "{val}"
      Environment: production'''
        benchmark_items.append({
            "id": f"cfn-sec-{i:04d}",
            "text": text,
            "value": val,
            "label": 1,
            "secret_type": "aws_access_key" if i % 2 == 0 else "aws_secret_key",
            "file_type": "cloudformation",
            "iac_type": "cloudformation",
            "cloud_provider": "aws",
            "aws_resource": res,
            "ci_cd_context": False,
            "is_placeholder": False,
            "expected_risk": "CRITICAL"
        })

    # 4. CloudFormation Clean (Safe)
    for i in range(70):
        res = random.choice(cfn_resources)
        text = f'''AWSTemplateFormatVersion: '2010-09-09'
Description: Serverless Stack
Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Sub "${{AWS::StackName}}-assets"'''
        benchmark_items.append({
            "id": f"cfn-clean-{i:04d}",
            "text": text,
            "value": "",
            "label": 0,
            "secret_type": "none",
            "file_type": "cloudformation",
            "iac_type": "cloudformation",
            "cloud_provider": "aws",
            "aws_resource": "AWS::S3::Bucket",
            "ci_cd_context": False,
            "is_placeholder": False,
            "expected_risk": "SAFE"
        })

    # 5. CI/CD Hardcoded Secrets (Critical)
    for i in range(90):
        platform = random.choice(["github_actions", "gitlab_ci", "jenkins"])
        val = _fake_gh_token() if i % 2 == 0 else _fake_aws_key()
        if platform == "github_actions":
            text = f'''name: Deploy Pipeline
on: [push]
jobs:
  release:
    runs-on: ubuntu-latest
    env:
      AWS_ACCESS_KEY_ID: "{val}"
    steps:
      - uses: actions/checkout@v4
      - run: ./publish.sh'''
        elif platform == "gitlab_ci":
            text = f'''stages:
  - deploy
deploy_prod:
  stage: deploy
  script:
    - export DEPLOY_TOKEN="{val}"
    - ./deploy.sh'''
        else:
            text = f'''pipeline {{
    agent any
    environment {{
        AWS_KEY = "{val}"
    }}
    stages {{
        stage('Deploy') {{
            steps {{ sh './deploy.sh' }}
        }}
    }}
}}'''
        benchmark_items.append({
            "id": f"cicd-sec-{i:04d}",
            "text": text,
            "value": val,
            "label": 1,
            "secret_type": "github_token" if "ghp_" in val else "aws_access_key",
            "file_type": platform,
            "iac_type": "none",
            "cloud_provider": "aws" if "AKIA" in val else "none",
            "aws_resource": "none",
            "ci_cd_context": True,
            "is_placeholder": False,
            "expected_risk": "CRITICAL"
        })

    # 6. CI/CD Secure References (Safe)
    for i in range(80):
        text = '''name: Secure CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    env:
      AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
      AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
    steps:
      - uses: actions/checkout@v4
      - run: npm test'''
        benchmark_items.append({
            "id": f"cicd-clean-{i:04d}",
            "text": text,
            "value": "",
            "label": 0,
            "secret_type": "none",
            "file_type": "github_actions",
            "iac_type": "none",
            "cloud_provider": "aws",
            "aws_resource": "none",
            "ci_cd_context": True,
            "is_placeholder": False,
            "expected_risk": "SAFE"
        })

    # 7. Documentation & Placeholders (Safe)
    placeholders = [
        "EXAMPLE_AWS_ACCESS_KEY",
        "YOUR_API_KEY_HERE",
        "REPLACE_ME_WITH_TOKEN",
        "<INSERT_PASSWORD>",
        "CHANGE_ME",
        "xxxx-xxxx-xxxx-xxxx"
    ]
    for i in range(80):
        ph = random.choice(placeholders)
        text = f'''# API Configuration Guide
To authenticate with the service, export your key:
```bash
export AWS_ACCESS_KEY_ID="{ph}"
export API_TOKEN="dummy_token_12345"
```
'''
        benchmark_items.append({
            "id": f"docs-ph-{i:04d}",
            "text": text,
            "value": ph,
            "label": 0,
            "secret_type": "placeholder",
            "file_type": "docs",
            "iac_type": "none",
            "cloud_provider": "none",
            "aws_resource": "none",
            "ci_cd_context": False,
            "is_placeholder": True,
            "expected_risk": "SAFE"
        })

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(benchmark_items, f, indent=2)
        
    print(f"[+] Generated {len(benchmark_items)} IaC/CI-CD benchmark samples to {output_path}")
    return benchmark_items


if __name__ == "__main__":
    generate_iac_benchmark(600)

