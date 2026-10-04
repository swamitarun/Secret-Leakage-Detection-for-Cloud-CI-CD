"""
Comprehensive Comparative Evaluation & Ablation Study Suite.
Compares:
  A. Regex only
  B. Regex + Entropy
  C. Regex + Entropy + IaC context
  D. Existing context-aware rules
  E. Transformer only
  F. Final Hybrid Transformer + Rules + Context
Runs on real datasets and produces genuine measured metrics.
"""

import os
import sys
import json
import time
from typing import List, Dict, Any, Tuple
import numpy as np
from tabulate import tabulate
import torch
from dataclasses import replace

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)

from scanner.scanner import scan_content, is_placeholder, shannon_entropy, PATTERNS
from scanner.iac_analyzer import analyze
from scanner.risk_engine import assess_risk
from ml.inference import SecretTransformerInference
from ml.utils import compute_classification_metrics, Timer
from ml.config import InferenceConfig


def evaluate_method_a_regex_only(samples: List[Dict[str, Any]]) -> Tuple[List[int], float]:
    """Method A: Naive Regex Only matching (no entropy, no placeholder filter)."""
    preds = []
    with Timer() as t:
        for s in samples:
            text = s["text"]
            matched = False
            for _, pattern, _ in PATTERNS:
                if pattern.search(text):
                    matched = True
                    break
            preds.append(1 if matched else 0)
    latency_ms = (t.elapsed_ms) / max(1, len(samples))
    return preds, latency_ms


def evaluate_method_b_regex_entropy(samples: List[Dict[str, Any]]) -> Tuple[List[int], float]:
    """Method B: Regex + Entropy filter (requires entropy >= 3.0 for matches)."""
    preds = []
    with Timer() as t:
        for s in samples:
            findings = scan_content(s["text"])
            matched = any(f.entropy >= 3.0 for f in findings)
            preds.append(1 if matched else 0)
    latency_ms = (t.elapsed_ms) / max(1, len(samples))
    return preds, latency_ms


def evaluate_method_c_regex_entropy_iac(samples: List[Dict[str, Any]]) -> Tuple[List[int], float]:
    """Method C: Regex + Entropy + IaC Context."""
    preds = []
    with Timer() as t:
        for s in samples:
            text = s["text"]
            findings = scan_content(text)
            ctx = analyze(s.get("file_type", "main.tf"), text)
            # Flag if non-placeholder findings and high entropy or in IaC
            has_secret = any((not f.is_placeholder and (f.entropy >= 2.8 or ctx.iac_type != "none")) for f in findings)
            preds.append(1 if has_secret else 0)
    latency_ms = (t.elapsed_ms) / max(1, len(samples))
    return preds, latency_ms


def evaluate_method_d_context_rules(samples: List[Dict[str, Any]]) -> Tuple[List[int], float]:
    """Method D: Full Existing Context-Aware Rules Engine."""
    preds = []
    with Timer() as t:
        for s in samples:
            text = s["text"]
            file_name = f"sample.{s.get('file_type', 'txt')}"
            findings = scan_content(text, file_name)
            ctx = analyze(file_name, text)
            assessment = assess_risk(file_name, findings, ctx)
            # Classified as positive if risk is HIGH or CRITICAL or MEDIUM (score >= 40)
            is_positive = 1 if assessment.risk_score >= 40 else 0
            preds.append(is_positive)
    latency_ms = (t.elapsed_ms) / max(1, len(samples))
    return preds, latency_ms


def evaluate_method_e_transformer(
    samples: List[Dict[str, Any]],
    infer_engine: SecretTransformerInference
) -> Tuple[List[int], float]:
    """Method E: Transformer Semantic Classifier."""
    texts = [s["text"] for s in samples]
    with Timer() as t:
        results = infer_engine.predict_batch(texts)
    preds = [1 if r["is_secret"] else 0 for r in results]
    latency_ms = (t.elapsed_ms) / max(1, len(samples))
    return preds, latency_ms


def _context_for_sample(sample: Dict[str, Any], disable_iac: bool = False,
                        disable_cicd: bool = False):
    """Build context from benchmark metadata, with explicit ablation switches."""
    file_type = sample.get("file_type", "txt")
    if file_type == "terraform":
        filename = "sample.tf"
    elif file_type == "cloudformation":
        filename = "sample.yaml"
    elif file_type in ("github_actions", "gitlab_ci", "jenkins"):
        filename = f"sample.{file_type}.yml"
    else:
        filename = "sample.txt"
    context = analyze(filename, sample["text"])
    if sample.get("iac_type") == "none" or disable_iac:
        context = replace(context, iac_type="none", aws_resources=[])
    if disable_cicd:
        context = replace(context, ci_cd_context=False, ci_cd_platform="none")
    return context


def evaluate_method_f_hybrid(
    samples: List[Dict[str, Any]],
    infer_engine: SecretTransformerInference,
    disable_iac: bool = False,
    disable_cicd: bool = False,
    disable_entropy: bool = False,
) -> Tuple[List[int], float]:
    """Method F: Hybrid Transformer + Context-Aware Rules + IaC Analyzer."""
    texts = [s["text"] for s in samples]
    with Timer() as t:
        dl_results = infer_engine.predict_batch(texts)
        preds = []
        for s, dl in zip(samples, dl_results):
            text = s["text"]
            file_name = f"sample.{s.get('file_type', 'txt')}"
            findings = scan_content(text, file_name)
            ctx = _context_for_sample(s, disable_iac, disable_cicd)
            if disable_entropy:
                findings = [replace(f, entropy=2.0) for f in findings]
            assessment = assess_risk(file_name, findings, ctx)
            
            # Hybrid Fusion Decision:
            # High risk if deterministic engine >= 60 OR (DL probability >= 0.75 and findings present)
            # Suppress if placeholder confirmed with low DL probability
            dl_prob = dl["probability"]
            rule_score = assessment.risk_score
            
            if assessment.risk_level in ("CRITICAL", "HIGH"):
                preds.append(1)
            elif dl_prob >= 0.65 and (findings or ctx.iac_type != "none" or ctx.ci_cd_context):
                preds.append(1)
            elif dl_prob >= 0.85:
                preds.append(1)
            elif rule_score >= 40 and dl_prob >= 0.3:
                preds.append(1)
            else:
                preds.append(0)
                
    latency_ms = (t.elapsed_ms) / max(1, len(samples))
    return preds, latency_ms


def run_full_comparative_benchmark(
    benchmark_path: str = "dataset/iac_cicd_benchmark.json",
    gpu_id: int | None = None
) -> Dict[str, Any]:
    """Run full comparative benchmark on the dataset."""
    print(f"[*] Loading benchmark from {benchmark_path}...")
    with open(benchmark_path, "r", encoding="utf-8") as f:
        samples = json.load(f)

    y_true = [s["label"] for s in samples]
    print(f"[*] Total Benchmark Samples: {len(samples)} (Positives: {sum(y_true)}, Negatives: {len(y_true) - sum(y_true)})")

    infer_engine = SecretTransformerInference(InferenceConfig(gpu_id=gpu_id))

    methods = [
        ("A. Regex Only", evaluate_method_a_regex_only(samples)),
        ("B. Regex + Entropy", evaluate_method_b_regex_entropy(samples)),
        ("C. Regex + Entropy + IaC", evaluate_method_c_regex_entropy_iac(samples)),
        ("D. Context-Aware Rules", evaluate_method_d_context_rules(samples)),
        ("E. Transformer (CodeBERT)", evaluate_method_e_transformer(samples, infer_engine)),
        ("F. Hybrid (Transformer + Rules)", evaluate_method_f_hybrid(samples, infer_engine)),
    ]

    table_data = []
    benchmark_results = {}

    for name, (preds, lat_ms) in methods:
        m = compute_classification_metrics(y_true, preds)
        m["latency_ms"] = round(lat_ms, 3)
        m["throughput_fps"] = round(1000.0 / max(0.001, lat_ms), 1)
        benchmark_results[name] = m
        table_data.append([
            name,
            f"{m['accuracy']:.4f}",
            f"{m['precision']:.4f}",
            f"{m['recall']:.4f}",
            f"{m['f1']:.4f}",
            f"{m['fp']}",
            f"{m['fn']}",
            f"{m['latency_ms']:.2f} ms"
        ])

    print("\n" + "=" * 80)
    print("  EXPERIMENT 1: COMPARATIVE MODEL BENCHMARK (IaC & CI/CD Suite)")
    print("=" * 80)
    headers = ["Method", "Accuracy", "Precision", "Recall", "F1 Score", "False Pos", "False Neg", "Latency"]
    print(tabulate(table_data, headers=headers, tablefmt="github"))
    print("=" * 80)

    # Save benchmark results
    out_dir = os.path.join(PROJECT_ROOT, "reports")
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "benchmark_results.json"), "w", encoding="utf-8") as f:
        json.dump(benchmark_results, f, indent=2)

    return benchmark_results


def run_ablation_study(
    benchmark_path: str = "dataset/iac_cicd_benchmark.json",
    gpu_id: int | None = None
) -> Dict[str, Any]:
    """
    Run ablation study by isolating and removing key context components:
    1. Full Hybrid System
    2. w/o IaC Resource Context
    3. w/o CI/CD Pipeline Context
    4. w/o Entropy Analysis
    5. w/o Transformer Semantic Embeddings
    """
    with open(benchmark_path, "r", encoding="utf-8") as f:
        samples = json.load(f)

    y_true = [s["label"] for s in samples]
    infer_engine = SecretTransformerInference(InferenceConfig(gpu_id=gpu_id))

    # Baseline: Full Hybrid
    preds_full, _ = evaluate_method_f_hybrid(samples, infer_engine)
    m_full = compute_classification_metrics(y_true, preds_full)

    # Ablation 1: w/o IaC Resource Context
    preds_no_iac, _ = evaluate_method_f_hybrid(samples, infer_engine, disable_iac=True)
    m_no_iac = compute_classification_metrics(y_true, preds_no_iac)

    # Ablation 2: w/o CI/CD Pipeline Context
    preds_no_cicd, _ = evaluate_method_f_hybrid(samples, infer_engine, disable_cicd=True)
    m_no_cicd = compute_classification_metrics(y_true, preds_no_cicd)

    # Ablation 3: w/o Entropy Analysis
    preds_no_ent = []
    for s in samples:
        findings = scan_content(s["text"])
        findings = [replace(f, entropy=2.0) for f in findings]
        ctx = _context_for_sample(s)
        a = assess_risk("sample.txt", findings, ctx)
        dl = infer_engine.predict_snippet(s["text"])
        preds_no_ent.append(1 if (a.risk_score >= 40 or dl["probability"] >= 0.7) else 0)
    m_no_ent = compute_classification_metrics(y_true, preds_no_ent)

    # Ablation 4: w/o Transformer (Rules only)
    preds_no_dl, _ = evaluate_method_d_context_rules(samples)
    m_no_dl = compute_classification_metrics(y_true, preds_no_dl)

    ablation_results = {
        "Full Hybrid Model": m_full,
        "w/o IaC Resource Context": m_no_iac,
        "w/o CI/CD Pipeline Context": m_no_cicd,
        "w/o Entropy Analysis": m_no_ent,
        "w/o Transformer Semantic Embedding": m_no_dl,
    }

    table_data = []
    for name, m in ablation_results.items():
        table_data.append([
            name,
            f"{m['accuracy']:.4f}",
            f"{m['precision']:.4f}",
            f"{m['recall']:.4f}",
            f"{m['f1']:.4f}",
            f"{m['fp']}",
            f"{m['fn']}"
        ])

    print("\n" + "=" * 80)
    print("  EXPERIMENT 2: ABLATION STUDY (Component Isolation)")
    print("=" * 80)
    headers = ["Configuration", "Accuracy", "Precision", "Recall", "F1 Score", "False Pos", "False Neg"]
    print(tabulate(table_data, headers=headers, tablefmt="github"))
    print("=" * 80)

    out_dir = os.path.join(PROJECT_ROOT, "reports")
    with open(os.path.join(out_dir, "ablation_results.json"), "w", encoding="utf-8") as f:
        json.dump(ablation_results, f, indent=2)

    return ablation_results


if __name__ == "__main__":
    benchmark_file = os.path.join(PROJECT_ROOT, "dataset", "iac_cicd_benchmark.json")
    if not os.path.exists(benchmark_file):
        from dataset.iac_benchmark import generate_iac_benchmark
        generate_iac_benchmark(600, benchmark_file)

    run_full_comparative_benchmark(benchmark_file)
    run_ablation_study(benchmark_file)
