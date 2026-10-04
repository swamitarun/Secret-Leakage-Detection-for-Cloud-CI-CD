"""
ML Configuration module for Transformer-based Context-Aware Secret Leakage Detection.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class ModelConfig:
    """Transformer Model Architecture & Pretrained weights configuration."""
    pretrained_model_name: str = "microsoft/codebert-base"
    num_labels: int = 2
    hidden_dropout_prob: float = 0.2
    classifier_dropout: float = 0.2
    use_context_features: bool = True
    context_feature_dim: int = 8  # entropy, is_iac, is_cicd, is_aws, has_secret_keyword, is_placeholder, content_length_norm, confidence
    fusion_hidden_dim: int = 128


@dataclass
class TrainingConfig:
    """Hyperparameters and runtime settings for training."""
    # Experiment & Paths
    experiment_name: str = "codebert_secret_detector"
    output_dir: str = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports", "checkpoints")
    best_model_path: str = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports", "transformer_secret_detector.pt")
    
    # Dataset
    dataset_name: str = "Podric/prowl-secrets-corpus"
    dataset_config: str = "corpus"
    train_subset_size: Optional[int] = 20000  # Default verified subset (can scale to 50k/100k+)
    val_subset_size: Optional[int] = 4000
    test_subset_size: Optional[int] = 4000
    seed: int = 42
    
    # Training Hyperparameters
    batch_size: int = 32
    eval_batch_size: int = 64
    num_epochs: int = 4
    learning_rate: float = 2e-5
    weight_decay: float = 0.01
    warmup_ratio: float = 0.1
    max_seq_length: int = 128
    gradient_accumulation_steps: int = 1
    max_grad_norm: float = 1.0
    
    # Hardware & Performance
    gpu_id: Optional[int] = None  # Select only after confirming a free GPU
    use_fp16: bool = True
    num_workers: int = 4
    
    # Early Stopping & Checkpointing
    early_stopping_patience: int = 3
    early_stopping_metric: str = "eval_f1"
    save_best_only: bool = True
    logging_steps: int = 50
    eval_steps: int = 200


@dataclass
class InferenceConfig:
    """Configuration for deployment and batch/single-sample inference."""
    model_path: str = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports", "transformer_secret_detector.pt")
    pretrained_model_name: str = "microsoft/codebert-base"
    max_seq_length: int = 128
    batch_size: int = 64
    gpu_id: Optional[int] = None
    device: str = "auto"  # or 'cpu'
    threshold: float = 0.5
