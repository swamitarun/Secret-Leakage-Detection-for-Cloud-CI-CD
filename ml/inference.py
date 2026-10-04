"""
Inference Engine for Transformer-Based Context-Aware Secret Leakage Detection.
Supports single-snippet and batch inference with GPU acceleration.
"""

import os
import sys
import torch
import numpy as np
from typing import List, Dict, Any, Union, Optional
from transformers import AutoTokenizer

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)

from ml.config import InferenceConfig, ModelConfig
from ml.model import SecretTransformerClassifier
from ml.preprocess import extract_context_features
from ml.utils import get_available_device


class SecretTransformerInference:
    """Production-grade inference pipeline for transformer secret detection."""
    
    _instance: Optional["SecretTransformerInference"] = None
    
    def __init__(self, config: Optional[InferenceConfig] = None):
        self.config = config or InferenceConfig()
        self.device = get_available_device(self.config.gpu_id)
        self.tokenizer = AutoTokenizer.from_pretrained(self.config.pretrained_model_name)
        self.model = None
        self._load_model()

    def _load_model(self):
        """Load trained weights from checkpoint."""
        if not os.path.exists(self.config.model_path):
            print(f"[!] Warning: Model checkpoint not found at {self.config.model_path}. Inference unavailable.", file=sys.stderr)
            return

        checkpoint = torch.load(self.config.model_path, map_location=self.device, weights_only=False)
        model_config = checkpoint.get("model_config", ModelConfig())
        self.model = SecretTransformerClassifier(model_config).to(self.device)
        self.model.load_state_dict(checkpoint["model_state_dict"])
        self.model.eval()

    @classmethod
    def get_instance(cls, config: Optional[InferenceConfig] = None) -> "SecretTransformerInference":
        """Singleton accessor for efficient model reuse."""
        if cls._instance is None:
            cls._instance = cls(config)
        return cls._instance

    def predict_snippet(
        self,
        text: str,
        candidate_value: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Predict whether a text snippet contains a secret.
        Returns: { 'is_secret': bool, 'confidence': float, 'probability': float }
        """
        if self.model is None:
            # Fallback if checkpoint is not trained yet
            return {"is_secret": False, "confidence": 0.0, "probability": 0.0, "available": False}

        features = extract_context_features(text, candidate_value)
        encoded = self.tokenizer(
            text,
            truncation=True,
            padding="max_length",
            max_length=self.config.max_seq_length,
            return_tensors="pt"
        )

        input_ids = encoded["input_ids"].to(self.device)
        attention_mask = encoded["attention_mask"].to(self.device)
        ctx_tensor = torch.tensor(features, dtype=torch.float32).unsqueeze(0).to(self.device)

        with torch.no_grad():
            outputs = self.model(
                input_ids=input_ids,
                attention_mask=attention_mask,
                context_features=ctx_tensor
            )
            prob_secret = float(outputs["probabilities"][0, 1].item())

        is_secret = prob_secret >= self.config.threshold
        confidence = prob_secret if is_secret else (1.0 - prob_secret)

        return {
            "is_secret": is_secret,
            "probability": round(prob_secret, 4),
            "confidence": round(confidence, 4),
            "available": True,
        }

    def predict_batch(
        self,
        texts: List[str],
        values: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """Run batch inference for higher throughput."""
        if self.model is None or not texts:
            return [{"is_secret": False, "confidence": 0.0, "probability": 0.0, "available": False} for _ in texts]

        results = []
        batch_size = self.config.batch_size
        
        for i in range(0, len(texts), batch_size):
            batch_texts = texts[i:i + batch_size]
            batch_values = values[i:i + batch_size] if values else [None] * len(batch_texts)

            features_list = [extract_context_features(t, v) for t, v in zip(batch_texts, batch_values)]
            encoded = self.tokenizer(
                batch_texts,
                truncation=True,
                padding="max_length",
                max_length=self.config.max_seq_length,
                return_tensors="pt"
            )

            input_ids = encoded["input_ids"].to(self.device)
            attention_mask = encoded["attention_mask"].to(self.device)
            ctx_tensor = torch.from_numpy(np.asarray(features_list, dtype=np.float32)).to(self.device)

            with torch.no_grad():
                outputs = self.model(
                    input_ids=input_ids,
                    attention_mask=attention_mask,
                    context_features=ctx_tensor
                )
                probs = outputs["probabilities"][:, 1].cpu().numpy()

            for p in probs:
                prob = float(p)
                is_sec = prob >= self.config.threshold
                conf = prob if is_sec else (1.0 - prob)
                results.append({
                    "is_secret": is_sec,
                    "probability": round(prob, 4),
                    "confidence": round(conf, 4),
                    "available": True,
                })

        return results
