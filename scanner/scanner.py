"""
Secret Scanner — regex + entropy + keyword based secret detection.

Detects:
  - AWS access key IDs  (AKIA pattern)
  - AWS secret access keys (40-char base64 after known variable names)
  - Generic API keys / tokens
  - Bearer tokens
  - GitHub personal access tokens (ghp_ / gho_ / ghu_ / ghs_ / ghr_)
  - Passwords (variable-name heuristic)
  - Private key headers (BEGIN RSA/EC/OPENSSH PRIVATE KEY)
  - Generic high-entropy credential assignments

All patterns are applied to synthetic/test data only.
No real credentials are ever processed.
"""

import re
import math
from dataclasses import dataclass


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class SecretFinding:
    """A single secret detected in a file."""
    secret_type: str          # e.g. "aws_access_key"
    matched_value: str        # the matched string (will be redacted in reports)
    line_number: int
    line_content: str
    entropy: float
    confidence: float         # 0.0–1.0
    is_placeholder: bool = False


# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

PATTERNS: list[tuple[str, re.Pattern, float]] = [
    # (secret_type, compiled_regex, base_confidence)

    # AWS access key — always starts with AKIA + 16 upper-alphanumeric chars
    ("aws_access_key",
     re.compile(r"""(?:^|["'\s=:])?(AKIA[0-9A-Z]{16})(?:["'\s,;]|$)"""),
     0.95),

    # AWS secret key — 40-char base64 string after a known variable name
    ("aws_secret_key",
     re.compile(
         r'(?:secret[_\- ]?(?:access[_\- ]?)?key|aws_secret_access_key)\s*'
         r'[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?',
         re.IGNORECASE),
     0.90),

    # GitHub personal access tokens (ghp_, gho_, ghu_, ghs_, ghr_, github_pat_)
    ("github_token",
     re.compile(r'(?:gh[pousr]_[A-Za-z0-9_]{30,}|github_pat_[A-Za-z0-9_]{22,})',
     re.IGNORECASE),
     0.92),

    # Bearer token in headers / assignments
    ("bearer_token",
     re.compile(
         r'(?:bearer|authorization)\s*[=:]\s*["\']?'
         r'Bearer\s+([A-Za-z0-9_\-\.]{20,})["\']?',
         re.IGNORECASE),
     0.85),

    # Password / passphrase assignments
    ("password",
     re.compile(
         r'(?:password|passwd|pass|db_password|master_password|'
         r'MasterUserPassword|admin_password|mysql_pwd|postgres_password)\s*'
         r'[=:]\s*["\']?([^\s"\'}{,;]{4,})["\']?',
         re.IGNORECASE),
     0.80),

    # API key assignments
    ("api_key",
     re.compile(
         r'(?:api[_\- ]?key|apikey|apiKey|API_KEY)\s*[=:]\s*["\']?'
         r'([A-Za-z0-9_\-]{16,})["\']?',
         re.IGNORECASE),
     0.75),

    # Token assignments
    ("token",
     re.compile(
         r'(?:token|auth_token|access_token|authToken|deploy_token|'
         r'DEPLOY_TOKEN|AUTH_TOKEN|SECRET_TOKEN)\s*[=:]\s*["\']?'
         r'([A-Za-z0-9_\-]{16,})["\']?',
         re.IGNORECASE),
     0.75),

    # Private key headers
    ("private_key",
     re.compile(
         r'-----BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+|DSA\s+)?PRIVATE\s+KEY-----',
         re.IGNORECASE),
     0.98),

    # Generic secret / credential assignments
    ("generic_secret",
     re.compile(
         r'(?:secret|credential|private_key|client_secret|'
         r'signing_key|encryption_key)\s*[=:]\s*["\']?'
         r'([A-Za-z0-9/+=_\-]{16,})["\']?',
         re.IGNORECASE),
     0.65),
]

# Strings that look like secrets but are actually placeholders / examples
PLACEHOLDER_PATTERNS = re.compile(
    r'^('
    r'REPLACE_ME.*|YOUR_.*|your[_-].*|<.*>|xxxx.*|TODO.*|CHANGEME.*|'
    r'CHANGE_ME.*|example[_-]?.*|test.*|dummy.*|fake.*|sample.*|'
    r'x{4,}|0{8,}|1{6,}|123456\d*|'
    r'AKIAIOSFODNN7EXAMPLE|wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY|'
    r'var\.\w+|\$\{\{.*\}\}'
    r')$',
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Entropy
# ---------------------------------------------------------------------------

def shannon_entropy(s: str) -> float:
    """Compute Shannon entropy of a string."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


# ---------------------------------------------------------------------------
# Placeholder detection
# ---------------------------------------------------------------------------

def is_placeholder(value: str) -> bool:
    """Return True if the value looks like a placeholder / example / test."""
    return bool(PLACEHOLDER_PATTERNS.match(value.strip()))


# ---------------------------------------------------------------------------
# Core scanning
# ---------------------------------------------------------------------------

def scan_content(content: str, filename: str = "<unknown>") -> list[SecretFinding]:
    """
    Scan file content for secrets.

    Returns a list of SecretFinding objects.
    """
    findings: list[SecretFinding] = []
    lines = content.splitlines()

    for line_no, line in enumerate(lines, start=1):
        # Skip comment-only lines in common formats
        stripped = line.strip()
        if stripped.startswith("#") and "key" not in stripped.lower():
            continue

        for secret_type, pattern, base_conf in PATTERNS:
            for match in pattern.finditer(line):
                # Private key has no capture group — use the whole match
                if secret_type == "private_key":
                    value = match.group(0)
                else:
                    value = match.group(1) if match.lastindex else match.group(0)
                value = value.strip("\"' ")

                if len(value) < 4:
                    continue

                placeholder = is_placeholder(value)
                ent = shannon_entropy(value)

                # Adjust confidence based on entropy & placeholder
                conf = base_conf
                if ent < 2.5 and secret_type != "private_key":
                    conf *= 0.5
                if placeholder:
                    conf *= 0.2

                findings.append(SecretFinding(
                    secret_type=secret_type,
                    matched_value=value,
                    line_number=line_no,
                    line_content=stripped,
                    entropy=round(ent, 4),
                    confidence=round(conf, 4),
                    is_placeholder=placeholder,
                ))

    return findings


def scan_file(filepath: str) -> list[SecretFinding]:
    """Convenience wrapper — read a file and scan it."""
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()
    return scan_content(content, filename=filepath)


def redact(value: str, show: int = 4) -> str:
    """Redact a secret value for safe display."""
    if len(value) <= show * 2:
        return "*" * len(value)
    return value[:show] + "*" * (len(value) - show * 2) + value[-show:]
