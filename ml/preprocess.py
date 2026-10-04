"""
Data preprocessing, cleaning, normalization, and context extraction for transformer training.
"""

import re
import math
import hashlib
from typing import Dict, Any, List, Tuple, Optional
import numpy as np


def compute_entropy(s: str) -> float:
    """Compute Shannon entropy of string."""
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


PLACEHOLDER_REGEX = re.compile(
    r'(?:REPLACE_ME|YOUR_.*|your[_-].*|<.*>|xxxx|TODO|CHANGEME|CHANGE_ME|'
    r'example|dummy|fake|sample|00000000|AKIAIOSFODNN7EXAMPLE|var\.\w+|\$\{\{.*\}\})',
    re.IGNORECASE
)

SECRET_KEYWORD_REGEX = re.compile(
    r'(?:key|secret|token|password|passwd|auth|api_key|access_key|private_key|credential)',
    re.IGNORECASE
)

AWS_KEYWORD_REGEX = re.compile(
    r'(?:aws|amazon|akia[0-9a-z]{16}|asia[0-9a-z]{16}|aws_|arn:aws:)',
    re.IGNORECASE
)

IAC_KEYWORD_REGEX = re.compile(
    r'(?:resource\s+"|AWSTemplateFormatVersion|terraform|provider\s+"|AWS::|variable\s+")',
    re.IGNORECASE
)

CICD_KEYWORD_REGEX = re.compile(
    r'(?:runs-on:|uses:\s+actions/|stages:|jenkinsfile|pipeline\s*\{|\.github/workflows)',
    re.IGNORECASE
)


def extract_context_features(text: str, value: Optional[str] = None) -> np.ndarray:
    """
    Extract an 8-dimensional normalized context vector:
    [0] Shannon entropy of candidate value or highest entropy token (0.0 to 1.0)
    [1] Is IaC context present (0.0 or 1.0)
    [2] Is CI/CD context present (0.0 or 1.0)
    [3] Is AWS context present (0.0 or 1.0)
    [4] Has secret-related keyword (0.0 or 1.0)
    [5] Is placeholder / example (0.0 or 1.0)
    [6] Content length normalized (0.0 to 1.0)
    [7] High entropy flag (> 3.5 entropy) (0.0 or 1.0)
    """
    text_str = str(text or "")
    val_str = str(value or "")
    
    if not val_str:
        # Find highest entropy token from text
        tokens = re.findall(r'[A-Za-z0-9_\-\.\/+]{6,}', text_str)
        if tokens:
            val_str = max(tokens, key=compute_entropy)
        else:
            val_str = text_str[:32]
            
    raw_ent = compute_entropy(val_str)
    norm_ent = min(raw_ent / 6.0, 1.0)
    
    is_iac = 1.0 if IAC_KEYWORD_REGEX.search(text_str) else 0.0
    is_cicd = 1.0 if CICD_KEYWORD_REGEX.search(text_str) else 0.0
    is_aws = 1.0 if AWS_KEYWORD_REGEX.search(text_str) else 0.0
    has_keyword = 1.0 if SECRET_KEYWORD_REGEX.search(text_str) else 0.0
    is_placeholder = 1.0 if PLACEHOLDER_REGEX.search(text_str) or PLACEHOLDER_REGEX.search(val_str) else 0.0
    norm_len = min(len(text_str) / 512.0, 1.0)
    is_high_ent = 1.0 if raw_ent >= 3.5 else 0.0
    
    return np.array([
        norm_ent,
        is_iac,
        is_cicd,
        is_aws,
        has_keyword,
        is_placeholder,
        norm_len,
        is_high_ent,
    ], dtype=np.float32)


def clean_prowl_sample(sample: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Clean and validate a single sample from Prowl Secrets Corpus.
    Returns cleaned dict or None if invalid.
    """
    text = sample.get("text", "")
    if not text or not isinstance(text, str):
        return None
    
    label = sample.get("label_binary", sample.get("label", None))
    if label is None:
        return None
    
    label = int(label)
    if label not in (0, 1):
        return None
    
    value = sample.get("value", "")
    secret_type = sample.get("label_type", sample.get("type", "unknown"))
    source = sample.get("source", "generic")
    
    # Generate content hash to prevent train/test leakage
    content_hash = hashlib.sha256(text.strip().encode("utf-8")).hexdigest()
    
    features = extract_context_features(text, value)
    
    return {
        "text": text.strip(),
        "value": str(value or ""),
        "label": label,
        "label_type": str(secret_type or "unknown"),
        "source": str(source or "unknown"),
        "features": features,
        "hash": content_hash,
    }
