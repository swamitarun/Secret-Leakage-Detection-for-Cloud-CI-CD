"""
Transformer Architecture for Context-Aware Secret Leakage Detection.
Integrates CodeBERT encoder with context feature fusion head.
"""

import torch
import torch.nn as nn
from typing import Optional, Dict, Any, Tuple
from transformers import AutoModel, AutoConfig

from ml.config import ModelConfig


class SecretTransformerClassifier(nn.Module):
    """
    Context-Aware Transformer Secret Classifier.
    Combines CodeBERT token representations with IaC & entropy context features.
    """
    
    def __init__(self, config: Optional[ModelConfig] = None):
        super().__init__()
        self.config = config or ModelConfig()
        
        # Load transformer encoder backbone
        self.encoder = AutoModel.from_pretrained(
            self.config.pretrained_model_name,
            use_safetensors=False
        )
        hidden_size = self.encoder.config.hidden_size  # 768 for CodeBERT
        
        self.dropout = nn.Dropout(self.config.hidden_dropout_prob)
        
        if self.config.use_context_features:
            # Context feature projection layer
            self.context_proj = nn.Sequential(
                nn.Linear(self.config.context_feature_dim, self.config.fusion_hidden_dim),
                nn.LayerNorm(self.config.fusion_hidden_dim),
                nn.GELU(),
                nn.Dropout(self.config.classifier_dropout),
            )
            total_dim = hidden_size + self.config.fusion_hidden_dim
        else:
            total_dim = hidden_size
            
        # Classification Head
        self.classifier = nn.Sequential(
            nn.Linear(total_dim, self.config.fusion_hidden_dim),
            nn.LayerNorm(self.config.fusion_hidden_dim),
            nn.GELU(),
            nn.Dropout(self.config.classifier_dropout),
            nn.Linear(self.config.fusion_hidden_dim, self.config.num_labels)
        )
        
        self.loss_fn = nn.CrossEntropyLoss()

    def forward(
        self,
        input_ids: torch.Tensor,
        attention_mask: torch.Tensor,
        context_features: Optional[torch.Tensor] = None,
        labels: Optional[torch.Tensor] = None
    ) -> Dict[str, torch.Tensor]:
        """
        Forward pass.
        Returns dict with 'logits', 'probabilities', and optional 'loss'.
        """
        outputs = self.encoder(input_ids=input_ids, attention_mask=attention_mask)
        # Use [CLS] token embedding (first token)
        cls_embedding = outputs.last_hidden_state[:, 0, :]
        cls_embedding = self.dropout(cls_embedding)
        
        if self.config.use_context_features and context_features is not None:
            ctx_emb = self.context_proj(context_features)
            fused_representation = torch.cat([cls_embedding, ctx_emb], dim=-1)
        else:
            fused_representation = cls_embedding
            
        logits = self.classifier(fused_representation)
        probabilities = torch.softmax(logits, dim=-1)
        
        result = {
            "logits": logits,
            "probabilities": probabilities,
        }
        
        if labels is not None:
            loss = self.loss_fn(logits, labels)
            result["loss"] = loss
            
        return result
