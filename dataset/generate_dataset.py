"""
Synthetic Dataset Generator for Context-Aware Secret Leakage Detection.

Generates labeled samples of source code / config files with and without
synthetic (fake) secrets across multiple file types:
  - Terraform (.tf)
  - CloudFormation (.yaml)
  - GitHub Actions workflow (.yml)
  - Python (.py)
  - Generic YAML / JSON / ENV

Every secret used is 100% synthetic — no real credentials are ever created.
"""

import os
import json
import csv
import random
import string
import math
import hashlib
from pathlib import Path

# ---------------------------------------------------------------------------
# Synthetic secret factories  (ALL FAKE — never real)
# ---------------------------------------------------------------------------

def _random_hex(n: int) -> str:
    return "".join(random.choices("0123456789abcdef", k=n))


def _random_alnum(n: int) -> str:
    return "".join(random.choices(string.ascii_letters + string.digits, k=n))


def _random_base64(n: int) -> str:
    chars = string.ascii_letters + string.digits + "+/"
    return "".join(random.choices(chars, k=n))


# Fake AWS access key IDs always start with AKIA + 16 alphanumeric chars
FAKE_AWS_ACCESS_KEYS = [
    f"AKIA{''.join(random.choices(string.ascii_uppercase + string.digits, k=16))}"
    for _ in range(20)
]

# Fake AWS secret keys — 40‑char base64‑ish strings
FAKE_AWS_SECRET_KEYS = [_random_base64(40) for _ in range(20)]

# Generic API keys / tokens
FAKE_API_KEYS = [_random_alnum(32) for _ in range(20)]
FAKE_TOKENS = [_random_hex(40) for _ in range(20)]

# Fake passwords
FAKE_PASSWORDS = [
    "SuperSecret123!", "P@ssw0rd!", "admin1234", "my_db_password_99",
    "hunter2", "correcthorsebatterystaple", "letmein2024",
    _random_alnum(16), _random_alnum(20), _random_alnum(12),
]

# Placeholder / example values (should be classified SAFE)
PLACEHOLDER_VALUES = [
    "REPLACE_ME", "your-api-key-here", "<INSERT_KEY>", "xxxx-xxxx-xxxx",
    "TODO", "CHANGEME", "example-token", "test", "dummy", "xxxxxxxx",
    "000000000000", "AKIAIOSFODNN7EXAMPLE",  # AWS example key from docs
]

# AWS resources used in Terraform / CloudFormation
AWS_RESOURCES_TF = [
    "aws_instance", "aws_s3_bucket", "aws_iam_role", "aws_iam_user",
    "aws_iam_policy", "aws_lambda_function", "aws_security_group",
    "aws_db_instance", "aws_ecs_task_definition", "aws_eks_cluster",
    "aws_secretsmanager_secret", "aws_kms_key", "aws_sns_topic",
    "aws_sqs_queue", "aws_dynamodb_table", "aws_cloudwatch_log_group",
    "aws_vpc", "aws_subnet", "aws_route_table", "aws_elastic_beanstalk_environment",
]

AWS_RESOURCES_CFN = [
    "AWS::EC2::Instance", "AWS::S3::Bucket", "AWS::IAM::Role",
    "AWS::IAM::User", "AWS::Lambda::Function", "AWS::EC2::SecurityGroup",
    "AWS::RDS::DBInstance", "AWS::ECS::TaskDefinition", "AWS::EKS::Cluster",
    "AWS::SecretsManager::Secret", "AWS::KMS::Key", "AWS::SNS::Topic",
    "AWS::SQS::Queue", "AWS::DynamoDB::Table", "AWS::Logs::LogGroup",
]

# ---------------------------------------------------------------------------
# Shannon entropy calculator
# ---------------------------------------------------------------------------

def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


# ---------------------------------------------------------------------------
# Template generators — produce (file_content, metadata_dict) tuples
# ---------------------------------------------------------------------------

def _gen_clean_terraform() -> tuple[str, dict]:
    """Clean Terraform file without secrets."""
    resource = random.choice(AWS_RESOURCES_TF)
    name = _random_alnum(6).lower()
    content = f'''provider "aws" {{
  region = "us-east-1"
}}

resource "{resource}" "{name}" {{
  tags = {{
    Name        = "{name}"
    Environment = "dev"
  }}
}}
'''
    return content, {
        "file_type": "terraform",
        "secret_type": "none",
        "secret_detected": False,
        "iac_type": "terraform",
        "cloud_provider": "aws",
        "aws_resource": resource,
        "ci_cd_context": False,
        "risk_level": "SAFE",
    }


def _gen_secret_terraform() -> tuple[str, dict]:
    """Terraform file with a fake embedded secret."""
    resource = random.choice(AWS_RESOURCES_TF)
    name = _random_alnum(6).lower()
    secret_kind = random.choice(["aws_access_key", "aws_secret_key", "password", "api_key"])

    if secret_kind == "aws_access_key":
        val = random.choice(FAKE_AWS_ACCESS_KEYS)
        attr = "access_key"
    elif secret_kind == "aws_secret_key":
        val = random.choice(FAKE_AWS_SECRET_KEYS)
        attr = "secret_key"
    elif secret_kind == "password":
        val = random.choice(FAKE_PASSWORDS)
        attr = "password"
    else:
        val = random.choice(FAKE_API_KEYS)
        attr = "api_key"

    content = f'''provider "aws" {{
  region = "us-east-1"
}}

resource "{resource}" "{name}" {{
  {attr} = "{val}"
  tags = {{
    Name        = "{name}"
    Environment = "production"
  }}
}}
'''
    return content, {
        "file_type": "terraform",
        "secret_type": secret_kind,
        "secret_detected": True,
        "iac_type": "terraform",
        "cloud_provider": "aws",
        "aws_resource": resource,
        "ci_cd_context": False,
        "risk_level": "CRITICAL",
    }


def _gen_placeholder_terraform() -> tuple[str, dict]:
    """Terraform file with a placeholder/example value — should be SAFE or LOW."""
    resource = random.choice(AWS_RESOURCES_TF)
    name = _random_alnum(6).lower()
    val = random.choice(PLACEHOLDER_VALUES)
    content = f'''resource "{resource}" "{name}" {{
  access_key = "{val}"
}}
'''
    return content, {
        "file_type": "terraform",
        "secret_type": "placeholder",
        "secret_detected": False,
        "iac_type": "terraform",
        "cloud_provider": "aws",
        "aws_resource": resource,
        "ci_cd_context": False,
        "risk_level": "SAFE",
    }


def _gen_clean_cloudformation() -> tuple[str, dict]:
    """Clean CloudFormation YAML without secrets."""
    resource = random.choice(AWS_RESOURCES_CFN)
    content = f"""AWSTemplateFormatVersion: '2010-09-09'
Description: Sample CloudFormation template
Resources:
  MyResource:
    Type: {resource}
    Properties:
      Tags:
        - Key: Environment
          Value: dev
"""
    return content, {
        "file_type": "cloudformation",
        "secret_type": "none",
        "secret_detected": False,
        "iac_type": "cloudformation",
        "cloud_provider": "aws",
        "aws_resource": resource,
        "ci_cd_context": False,
        "risk_level": "SAFE",
    }


def _gen_secret_cloudformation() -> tuple[str, dict]:
    """CloudFormation template with a fake secret."""
    resource = random.choice(AWS_RESOURCES_CFN)
    secret_kind = random.choice(["aws_access_key", "aws_secret_key", "password"])
    if secret_kind == "aws_access_key":
        val = random.choice(FAKE_AWS_ACCESS_KEYS)
        prop = "AccessKeyId"
    elif secret_kind == "aws_secret_key":
        val = random.choice(FAKE_AWS_SECRET_KEYS)
        prop = "SecretAccessKey"
    else:
        val = random.choice(FAKE_PASSWORDS)
        prop = "MasterUserPassword"

    content = f"""AWSTemplateFormatVersion: '2010-09-09'
Description: CloudFormation template with credential
Resources:
  MyResource:
    Type: {resource}
    Properties:
      {prop}: "{val}"
      Tags:
        - Key: Environment
          Value: production
"""
    return content, {
        "file_type": "cloudformation",
        "secret_type": secret_kind,
        "secret_detected": True,
        "iac_type": "cloudformation",
        "cloud_provider": "aws",
        "aws_resource": resource,
        "ci_cd_context": False,
        "risk_level": "CRITICAL",
    }


def _gen_clean_github_actions() -> tuple[str, dict]:
    """Clean GitHub Actions workflow without secrets."""
    content = """name: CI
on: [push, pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run tests
        run: pytest
"""
    return content, {
        "file_type": "github_actions",
        "secret_type": "none",
        "secret_detected": False,
        "iac_type": "none",
        "cloud_provider": "none",
        "aws_resource": "none",
        "ci_cd_context": True,
        "risk_level": "SAFE",
    }


def _gen_secret_github_actions() -> tuple[str, dict]:
    """GitHub Actions workflow with a hardcoded fake secret."""
    secret_kind = random.choice(["aws_access_key", "aws_secret_key", "token", "api_key"])
    if secret_kind == "aws_access_key":
        val = random.choice(FAKE_AWS_ACCESS_KEYS)
        env_name = "AWS_ACCESS_KEY_ID"
    elif secret_kind == "aws_secret_key":
        val = random.choice(FAKE_AWS_SECRET_KEYS)
        env_name = "AWS_SECRET_ACCESS_KEY"
    elif secret_kind == "token":
        val = random.choice(FAKE_TOKENS)
        env_name = "DEPLOY_TOKEN"
    else:
        val = random.choice(FAKE_API_KEYS)
        env_name = "API_KEY"

    content = f"""name: Deploy
on:
  push:
    branches: [main]
jobs:
  deploy:
    runs-on: ubuntu-latest
    env:
      {env_name}: "{val}"
    steps:
      - uses: actions/checkout@v4
      - name: Deploy
        run: ./deploy.sh
"""
    return content, {
        "file_type": "github_actions",
        "secret_type": secret_kind,
        "secret_detected": True,
        "iac_type": "none",
        "cloud_provider": "aws" if "aws" in secret_kind else "none",
        "aws_resource": "none",
        "ci_cd_context": True,
        "risk_level": "CRITICAL",
    }


def _gen_clean_python() -> tuple[str, dict]:
    """Clean Python file."""
    content = '''import os
import logging

logger = logging.getLogger(__name__)

def process_data(data: list) -> list:
    """Process input data."""
    return [item.strip() for item in data if item]

if __name__ == "__main__":
    sample = ["hello ", " world", ""]
    print(process_data(sample))
'''
    return content, {
        "file_type": "python",
        "secret_type": "none",
        "secret_detected": False,
        "iac_type": "none",
        "cloud_provider": "none",
        "aws_resource": "none",
        "ci_cd_context": False,
        "risk_level": "SAFE",
    }


def _gen_secret_python() -> tuple[str, dict]:
    """Python file with a hardcoded fake credential."""
    secret_kind = random.choice(["aws_access_key", "aws_secret_key", "password", "api_key", "token"])
    if secret_kind == "aws_access_key":
        var, val = "AWS_ACCESS_KEY_ID", random.choice(FAKE_AWS_ACCESS_KEYS)
    elif secret_kind == "aws_secret_key":
        var, val = "AWS_SECRET_ACCESS_KEY", random.choice(FAKE_AWS_SECRET_KEYS)
    elif secret_kind == "password":
        var, val = "DB_PASSWORD", random.choice(FAKE_PASSWORDS)
    elif secret_kind == "api_key":
        var, val = "API_KEY", random.choice(FAKE_API_KEYS)
    else:
        var, val = "AUTH_TOKEN", random.choice(FAKE_TOKENS)

    content = f'''import os

{var} = "{val}"

def connect():
    """Connect using credentials."""
    return {var}

if __name__ == "__main__":
    connect()
'''
    # Python with AWS cred → HIGH; other secrets → HIGH
    risk = "HIGH" if "aws" in secret_kind else "HIGH"
    return content, {
        "file_type": "python",
        "secret_type": secret_kind,
        "secret_detected": True,
        "iac_type": "none",
        "cloud_provider": "aws" if "aws" in secret_kind else "none",
        "aws_resource": "none",
        "ci_cd_context": False,
        "risk_level": risk,
    }


def _gen_env_file(with_secret: bool) -> tuple[str, dict]:
    """Generate a .env-style config file."""
    if with_secret:
        secret_kind = random.choice(["aws_access_key", "password", "api_key", "token"])
        if secret_kind == "aws_access_key":
            line = f"AWS_ACCESS_KEY_ID={random.choice(FAKE_AWS_ACCESS_KEYS)}"
        elif secret_kind == "password":
            line = f"DB_PASSWORD={random.choice(FAKE_PASSWORDS)}"
        elif secret_kind == "api_key":
            line = f"API_KEY={random.choice(FAKE_API_KEYS)}"
        else:
            line = f"AUTH_TOKEN={random.choice(FAKE_TOKENS)}"

        content = f"""# Application config
APP_NAME=myapp
ENV=production
{line}
LOG_LEVEL=info
"""
        return content, {
            "file_type": "env",
            "secret_type": secret_kind,
            "secret_detected": True,
            "iac_type": "none",
            "cloud_provider": "aws" if "aws" in secret_kind else "none",
            "aws_resource": "none",
            "ci_cd_context": False,
            "risk_level": "HIGH",
        }
    else:
        content = """# Application config
APP_NAME=myapp
ENV=development
LOG_LEVEL=debug
PORT=8080
"""
        return content, {
            "file_type": "env",
            "secret_type": "none",
            "secret_detected": False,
            "iac_type": "none",
            "cloud_provider": "none",
            "aws_resource": "none",
            "ci_cd_context": False,
            "risk_level": "SAFE",
        }


def _gen_json_config(with_secret: bool) -> tuple[str, dict]:
    """Generate a JSON config file."""
    if with_secret:
        secret_kind = random.choice(["api_key", "token", "password"])
        if secret_kind == "api_key":
            val = random.choice(FAKE_API_KEYS)
            key = "apiKey"
        elif secret_kind == "token":
            val = random.choice(FAKE_TOKENS)
            key = "authToken"
        else:
            val = random.choice(FAKE_PASSWORDS)
            key = "dbPassword"

        obj = {
            "app": "myservice",
            "environment": "production",
            key: val,
            "port": 3000,
        }
        content = json.dumps(obj, indent=2) + "\n"
        return content, {
            "file_type": "json",
            "secret_type": secret_kind,
            "secret_detected": True,
            "iac_type": "none",
            "cloud_provider": "none",
            "aws_resource": "none",
            "ci_cd_context": False,
            "risk_level": "HIGH",
        }
    else:
        obj = {"app": "myservice", "environment": "development", "port": 3000, "debug": True}
        content = json.dumps(obj, indent=2) + "\n"
        return content, {
            "file_type": "json",
            "secret_type": "none",
            "secret_detected": False,
            "iac_type": "none",
            "cloud_provider": "none",
            "aws_resource": "none",
            "ci_cd_context": False,
            "risk_level": "SAFE",
        }


def _gen_yaml_config(with_secret: bool) -> tuple[str, dict]:
    """Generate a generic YAML config file."""
    if with_secret:
        secret_kind = random.choice(["password", "api_key", "token"])
        if secret_kind == "password":
            val = random.choice(FAKE_PASSWORDS)
            key = "db_password"
        elif secret_kind == "api_key":
            val = random.choice(FAKE_API_KEYS)
            key = "api_key"
        else:
            val = random.choice(FAKE_TOKENS)
            key = "auth_token"

        content = f"""app:
  name: myservice
  environment: production
  {key}: "{val}"
  port: 8080
"""
        return content, {
            "file_type": "yaml",
            "secret_type": secret_kind,
            "secret_detected": True,
            "iac_type": "none",
            "cloud_provider": "none",
            "aws_resource": "none",
            "ci_cd_context": False,
            "risk_level": "HIGH",
        }
    else:
        content = """app:
  name: myservice
  environment: development
  port: 8080
  debug: true
"""
        return content, {
            "file_type": "yaml",
            "secret_type": "none",
            "secret_detected": False,
            "iac_type": "none",
            "cloud_provider": "none",
            "aws_resource": "none",
            "ci_cd_context": False,
            "risk_level": "SAFE",
        }


def _gen_secret_env_var_python() -> tuple[str, dict]:
    """Python file using os.environ with a hardcoded fallback secret."""
    val = random.choice(FAKE_AWS_ACCESS_KEYS)
    content = f'''import os

# Fallback to hardcoded key — BAD PRACTICE
aws_key = os.environ.get("AWS_ACCESS_KEY_ID", "{val}")
'''
    return content, {
        "file_type": "python",
        "secret_type": "aws_access_key",
        "secret_detected": True,
        "iac_type": "none",
        "cloud_provider": "aws",
        "aws_resource": "none",
        "ci_cd_context": False,
        "risk_level": "HIGH",
    }


def _gen_terraform_with_var_reference() -> tuple[str, dict]:
    """Terraform file using var.* reference — no hardcoded secret → LOW risk."""
    resource = random.choice(AWS_RESOURCES_TF)
    content = f'''variable "db_password" {{
  description = "Database password"
  type        = string
  sensitive   = true
}}

resource "{resource}" "db" {{
  password = var.db_password
}}
'''
    return content, {
        "file_type": "terraform",
        "secret_type": "none",
        "secret_detected": False,
        "iac_type": "terraform",
        "cloud_provider": "aws",
        "aws_resource": resource,
        "ci_cd_context": False,
        "risk_level": "SAFE",
    }


def _gen_github_actions_with_secrets_ref() -> tuple[str, dict]:
    """GitHub Actions using ${{ secrets.* }} — proper practice → SAFE."""
    content = """name: Secure Deploy
on:
  push:
    branches: [main]
jobs:
  deploy:
    runs-on: ubuntu-latest
    env:
      AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
      AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
    steps:
      - uses: actions/checkout@v4
      - name: Deploy
        run: ./deploy.sh
"""
    return content, {
        "file_type": "github_actions",
        "secret_type": "none",
        "secret_detected": False,
        "iac_type": "none",
        "cloud_provider": "aws",
        "aws_resource": "none",
        "ci_cd_context": True,
        "risk_level": "SAFE",
    }


# ---------------------------------------------------------------------------
# Master generator
# ---------------------------------------------------------------------------

# Weighted distribution of sample generators
GENERATORS = [
    (_gen_clean_terraform, 8),
    (_gen_secret_terraform, 12),
    (_gen_placeholder_terraform, 5),
    (_gen_terraform_with_var_reference, 5),
    (_gen_clean_cloudformation, 6),
    (_gen_secret_cloudformation, 10),
    (_gen_clean_github_actions, 5),
    (_gen_secret_github_actions, 10),
    (_gen_github_actions_with_secrets_ref, 5),
    (_gen_clean_python, 6),
    (_gen_secret_python, 8),
    (_gen_secret_env_var_python, 4),
    (lambda: _gen_env_file(False), 4),
    (lambda: _gen_env_file(True), 5),
    (lambda: _gen_json_config(False), 3),
    (lambda: _gen_json_config(True), 5),
    (lambda: _gen_yaml_config(False), 3),
    (lambda: _gen_yaml_config(True), 5),
]

FILE_EXTENSIONS = {
    "terraform": ".tf",
    "cloudformation": ".yaml",
    "github_actions": ".yml",
    "python": ".py",
    "env": ".env",
    "json": ".json",
    "yaml": ".yaml",
}


def generate_dataset(n_samples: int, output_dir: str, seed: int = 42) -> str:
    """
    Generate *n_samples* synthetic labelled files and a metadata CSV.

    Returns the path to the metadata CSV.
    """
    random.seed(seed)
    os.makedirs(output_dir, exist_ok=True)

    # Build weighted list
    weighted: list = []
    for gen_fn, weight in GENERATORS:
        weighted.extend([gen_fn] * weight)

    metadata_rows: list[dict] = []

    for i in range(n_samples):
        gen_fn = random.choice(weighted)
        content, meta = gen_fn()

        ext = FILE_EXTENSIONS.get(meta["file_type"], ".txt")
        filename = f"sample_{i:05d}{ext}"
        filepath = os.path.join(output_dir, filename)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)

        # Compute entropy of the embedded secret value (if any)
        # We approximate by taking entropy of the whole content
        meta["filename"] = filename
        meta["entropy"] = round(shannon_entropy(content), 4)
        meta["content_length"] = len(content)
        meta["sample_id"] = i
        metadata_rows.append(meta)

    # Write CSV
    csv_path = os.path.join(output_dir, "metadata.csv")
    fieldnames = [
        "sample_id", "filename", "file_type", "secret_type",
        "secret_detected", "iac_type", "cloud_provider", "aws_resource",
        "ci_cd_context", "entropy", "content_length", "risk_level",
    ]
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(metadata_rows)

    print(f"[+] Generated {n_samples} samples in {output_dir}")
    print(f"[+] Metadata written to {csv_path}")
    return csv_path


# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Generate synthetic secret-leakage dataset")
    parser.add_argument("-n", "--num-samples", type=int, default=100,
                        help="Number of samples to generate (default: 100)")
    parser.add_argument("-o", "--output-dir", type=str, default="dataset/generated",
                        help="Output directory")
    parser.add_argument("-s", "--seed", type=int, default=42,
                        help="Random seed for reproducibility")
    args = parser.parse_args()

    generate_dataset(args.num_samples, args.output_dir, args.seed)
