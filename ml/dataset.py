"""
PyTorch Dataset and DataLoader pipelines for Transformer-based secret detection.
"""

import os
import random
import torch
from torch.utils.data import Dataset, DataLoader
from typing import List, Dict, Any, Tuple, Optional
from datasets import load_dataset
from transformers import AutoTokenizer

from ml.config import TrainingConfig, ModelConfig
from ml.preprocess import clean_prowl_sample, extract_context_features


class SecretDataset(Dataset):
    """PyTorch Dataset containing tokenized text snippets, context vectors, and binary labels."""
    
    def __init__(
        self,
        samples: List[Dict[str, Any]],
        tokenizer: AutoTokenizer,
        max_length: int = 128,
        include_context_features: bool = True
    ):
        self.samples = samples
        self.tokenizer = tokenizer
        self.max_length = max_length
        self.include_context_features = include_context_features

    def __len__(self) -> int:
        return len(self.samples)

    def __getitem__(self, idx: int) -> Dict[str, torch.Tensor]:
        sample = self.samples[idx]
        text = sample["text"]
        label = sample["label"]
        features = sample["features"]
        
        encoded = self.tokenizer(
            text,
            truncation=True,
            padding="max_length",
            max_length=self.max_length,
            return_tensors="pt"
        )
        
        item = {
            "input_ids": encoded["input_ids"].squeeze(0),
            "attention_mask": encoded["attention_mask"].squeeze(0),
            "label": torch.tensor(label, dtype=torch.long),
        }
        
        if self.include_context_features:
            item["context_features"] = torch.tensor(features, dtype=torch.float32)
            
        return item


def load_prowl_splits(
    config: TrainingConfig,
    tokenizer: AutoTokenizer
) -> Tuple[SecretDataset, SecretDataset, SecretDataset]:
    """
    Loads and prepares the Prowl Secrets Corpus with deduplication and stratified splits.
    Ensures zero data leakage between train, val, and test splits.
    """
    print(f"[*] Loading dataset '{config.dataset_name}' (config: {config.dataset_config})...")
    raw_dataset = load_dataset(config.dataset_name, config.dataset_config, split="train")
    
    # Clean and deduplicate samples
    seen_hashes = set()
    cleaned_positives = []
    cleaned_negatives = []
    
    total_raw = len(raw_dataset)
    target_total = (config.train_subset_size or 20000) + (config.val_subset_size or 4000) + (config.test_subset_size or 4000)
    
    # Collect balanced samples
    for i in range(total_raw):
        sample = raw_dataset[i]
        cleaned = clean_prowl_sample(sample)
        if cleaned is None:
            continue
            
        h = cleaned["hash"]
        if h in seen_hashes:
            continue
        seen_hashes.add(h)
        
        if cleaned["label"] == 1:
            cleaned_positives.append(cleaned)
        else:
            cleaned_negatives.append(cleaned)
            
        # Break early once we have ample balanced samples
        if len(cleaned_positives) >= target_total and len(cleaned_negatives) >= target_total:
            break
            
    print(f"[*] Extracted unique samples: {len(cleaned_positives)} Positives (Secrets), {len(cleaned_negatives)} Negatives (Safe)")
    
    # Stratified balance
    random.seed(config.seed)
    random.shuffle(cleaned_positives)
    random.shuffle(cleaned_negatives)
    
    n_train_half = (config.train_subset_size or 20000) // 2
    n_val_half = (config.val_subset_size or 4000) // 2
    n_test_half = (config.test_subset_size or 4000) // 2
    
    # Adjust if negatives are fewer
    n_train_neg = min(n_train_half, len(cleaned_negatives) - n_val_half - n_test_half)
    
    train_samples = cleaned_positives[:n_train_half] + cleaned_negatives[:n_train_neg]
    val_samples = cleaned_positives[n_train_half:n_train_half + n_val_half] + cleaned_negatives[n_train_neg:n_train_neg + n_val_half]
    test_samples = cleaned_positives[n_train_half + n_val_half:n_train_half + n_val_half + n_test_half] + cleaned_negatives[n_train_neg + n_val_half:n_train_neg + n_val_half + n_test_half]
    
    random.shuffle(train_samples)
    random.shuffle(val_samples)
    random.shuffle(test_samples)
    
    print(f"[*] Final Splits -> Train: {len(train_samples)}, Val: {len(val_samples)}, Test: {len(test_samples)}")
    
    train_dataset = SecretDataset(train_samples, tokenizer, config.max_seq_length)
    val_dataset = SecretDataset(val_samples, tokenizer, config.max_seq_length)
    test_dataset = SecretDataset(test_samples, tokenizer, config.max_seq_length)
    
    return train_dataset, val_dataset, test_dataset


def create_dataloaders(
    train_dataset: SecretDataset,
    val_dataset: SecretDataset,
    test_dataset: SecretDataset,
    config: TrainingConfig
) -> Tuple[DataLoader, DataLoader, DataLoader]:
    """Create PyTorch DataLoaders for train, val, and test splits."""
    train_loader = DataLoader(
        train_dataset,
        batch_size=config.batch_size,
        shuffle=True,
        num_workers=config.num_workers,
        pin_memory=torch.cuda.is_available()
    )
    val_loader = DataLoader(
        val_dataset,
        batch_size=config.eval_batch_size,
        shuffle=False,
        num_workers=config.num_workers,
        pin_memory=torch.cuda.is_available()
    )
    test_loader = DataLoader(
        test_dataset,
        batch_size=config.eval_batch_size,
        shuffle=False,
        num_workers=config.num_workers,
        pin_memory=torch.cuda.is_available()
    )
    return train_loader, val_loader, test_loader
