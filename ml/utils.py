"""
Utility functions for deep learning training, hardware detection, metrics, and evaluation.
"""

import os
import random
import time
import torch
import numpy as np
from typing import Dict, Any, List, Optional, Tuple


def set_seed(seed: int = 42) -> None:
    """Set random seeds for full reproducibility across python, numpy, and pytorch."""
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)
        torch.backends.cudnn.deterministic = True
        torch.backends.cudnn.benchmark = False


def get_available_device(preferred_gpu: Optional[int] = None) -> torch.device:
    """
    Select an available CUDA device or fallback to CPU cleanly.
    Validates that the preferred GPU is accessible.
    """
    if not torch.cuda.is_available():
        return torch.device("cpu")
    
    device_count = torch.cuda.device_count()
    if preferred_gpu is not None and 0 <= preferred_gpu < device_count:
        return torch.device(f"cuda:{preferred_gpu}")
    
    # Fallback to cuda:0 if preferred_gpu is invalid
    return torch.device("cuda:0")


def compute_classification_metrics(
    y_true: List[int],
    y_pred: List[int],
    y_prob: Optional[List[float]] = None
) -> Dict[str, Any]:
    """
    Compute comprehensive classification metrics:
    - Precision, Recall, F1, Accuracy
    - Confusion Matrix [TN, FP, FN, TP]
    - False Positive & False Negative Rates
    - ROC-AUC (if probabilities provided)
    """
    y_true_np = np.array(y_true)
    y_pred_np = np.array(y_pred)

    tp = int(np.sum((y_true_np == 1) & (y_pred_np == 1)))
    fp = int(np.sum((y_true_np == 0) & (y_pred_np == 1)))
    tn = int(np.sum((y_true_np == 0) & (y_pred_np == 0)))
    fn = int(np.sum((y_true_np == 1) & (y_pred_np == 0)))

    accuracy = (tp + tn) / max(1, len(y_true_np))
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    f1 = (2 * precision * recall / (precision + recall)
          if precision + recall else 0.0)
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

    metrics = {
        "accuracy": round(float(accuracy), 4),
        "precision": round(float(precision), 4),
        "recall": round(float(recall), 4),
        "f1": round(float(f1), 4),
        "confusion_matrix": [[tn, fp], [fn, tp]],
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "false_positive_rate": round(float(fpr), 4),
        "false_negative_rate": round(float(fnr), 4),
    }

    if y_prob is not None:
        try:
            positive_count = int(np.sum(y_true_np == 1))
            negative_count = int(np.sum(y_true_np == 0))
            if not positive_count or not negative_count:
                raise ValueError("ROC-AUC requires both classes")
            order = np.argsort(np.asarray(y_prob))
            ranks = np.empty(len(order), dtype=float)
            ranks[order] = np.arange(1, len(order) + 1)
            positive_rank_sum = float(np.sum(ranks[y_true_np == 1]))
            auc = ((positive_rank_sum - positive_count * (positive_count + 1) / 2)
                   / (positive_count * negative_count))
            metrics["roc_auc"] = round(float(auc), 4)
        except Exception:
            metrics["roc_auc"] = None

    return metrics


class Timer:
    """Context manager for accurate wall-clock and GPU timing."""
    def __enter__(self):
        if torch.cuda.is_available():
            torch.cuda.synchronize()
        self.start = time.perf_counter()
        return self

    def __exit__(self, *args):
        if torch.cuda.is_available():
            torch.cuda.synchronize()
        self.elapsed = time.perf_counter() - self.start
        self.elapsed_ms = self.elapsed * 1000
