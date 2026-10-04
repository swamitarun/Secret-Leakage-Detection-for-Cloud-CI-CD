"""
Training Pipeline for Transformer-Based Context-Aware Secret Leakage Detection.
Supports CUDA GPU ID selection, Mixed Precision (FP16), Early Stopping, and Checkpointing.
"""

import os
import sys
import json
import time
import argparse
import torch
from torch.optim import AdamW
from torch.cuda.amp import autocast, GradScaler
from transformers import AutoTokenizer, get_cosine_schedule_with_warmup

# Add project root to sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)

from ml.config import TrainingConfig, ModelConfig
from ml.utils import set_seed, get_available_device, compute_classification_metrics
from ml.dataset import load_prowl_splits, create_dataloaders
from ml.model import SecretTransformerClassifier


def evaluate_model(
    model: torch.nn.Module,
    data_loader: torch.utils.data.DataLoader,
    device: torch.device,
    use_fp16: bool = True
) -> dict:
    """Evaluate model performance on a DataLoader."""
    model.eval()
    total_loss = 0.0
    all_preds = []
    all_labels = []
    all_probs = []

    with torch.no_grad():
        for batch in data_loader:
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            labels = batch["label"].to(device)
            context_features = batch.get("context_features")
            if context_features is not None:
                context_features = context_features.to(device)

            with autocast(enabled=use_fp16 and device.type == "cuda"):
                outputs = model(
                    input_ids=input_ids,
                    attention_mask=attention_mask,
                    context_features=context_features,
                    labels=labels
                )

            total_loss += outputs["loss"].item()
            probs = outputs["probabilities"][:, 1].cpu().numpy()
            preds = torch.argmax(outputs["logits"], dim=-1).cpu().numpy()

            all_preds.extend(preds.tolist())
            all_labels.extend(labels.cpu().numpy().tolist())
            all_probs.extend(probs.tolist())

    avg_loss = total_loss / max(1, len(data_loader))
    metrics = compute_classification_metrics(all_labels, all_preds, all_probs)
    metrics["loss"] = round(float(avg_loss), 4)
    return metrics


def train_transformer(
    config: TrainingConfig,
    model_config: ModelConfig,
    resume_path: str | None = None,
) -> dict:
    """Train the Context-Aware Secret Transformer Model."""
    set_seed(config.seed)
    device = get_available_device(config.gpu_id)
    print(f"[*] Training on device: {device} ({torch.cuda.get_device_name(device) if device.type == 'cuda' else 'CPU'})")

    # Load Tokenizer & Datasets
    tokenizer = AutoTokenizer.from_pretrained(model_config.pretrained_model_name)
    train_dataset, val_dataset, test_dataset = load_prowl_splits(config, tokenizer)
    train_loader, val_loader, test_loader = create_dataloaders(train_dataset, val_dataset, test_dataset, config)

    # Initialize Model
    model = SecretTransformerClassifier(model_config).to(device)
    resume_checkpoint = None
    start_epoch = 1
    if resume_path:
        resume_checkpoint = torch.load(resume_path, map_location=device, weights_only=False)
        model.load_state_dict(resume_checkpoint["model_state_dict"])
        start_epoch = int(resume_checkpoint.get("epoch", 0)) + 1
        print(f"[*] Resuming model weights from epoch {start_epoch - 1}: {resume_path}")

    # Optimizer & LR Scheduler
    no_decay = ["bias", "LayerNorm.weight"]
    optimizer_grouped_parameters = [
        {
            "params": [p for n, p in model.named_parameters() if not any(nd in n for nd in no_decay)],
            "weight_decay": config.weight_decay,
        },
        {
            "params": [p for n, p in model.named_parameters() if any(nd in n for nd in no_decay)],
            "weight_decay": 0.0,
        },
    ]
    optimizer = AdamW(optimizer_grouped_parameters, lr=config.learning_rate)

    total_steps = (len(train_loader) // config.gradient_accumulation_steps) * config.num_epochs
    warmup_steps = int(total_steps * config.warmup_ratio)
    scheduler = get_cosine_schedule_with_warmup(
        optimizer,
        num_warmup_steps=warmup_steps,
        num_training_steps=total_steps
    )

    scaler = GradScaler(enabled=config.use_fp16 and device.type == "cuda")

    best_val_f1 = float((resume_checkpoint or {}).get("val_metrics", {}).get("f1", -1.0))
    patience_counter = 0
    history = []

    print("\n" + "=" * 64)
    print(f"  STARTING TRANSFORMER TRAINING ({config.num_epochs} Epochs)")
    print(f"  Batch size: {config.batch_size} | LR: {config.learning_rate} | FP16: {config.use_fp16}")
    print("=" * 64)
    print("  Progress updates include percentage, elapsed time, and ETA.", flush=True)

    start_time = time.time()

    for epoch in range(start_epoch, config.num_epochs + 1):
        model.train()
        running_loss = 0.0
        epoch_start = time.time()

        for step, batch in enumerate(train_loader, 1):
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            labels = batch["label"].to(device)
            context_features = batch.get("context_features")
            if context_features is not None:
                context_features = context_features.to(device)

            with autocast(enabled=config.use_fp16 and device.type == "cuda"):
                outputs = model(
                    input_ids=input_ids,
                    attention_mask=attention_mask,
                    context_features=context_features,
                    labels=labels
                )
                loss = outputs["loss"] / config.gradient_accumulation_steps

            scaler.scale(loss).backward()
            running_loss += loss.item() * config.gradient_accumulation_steps

            if step % config.gradient_accumulation_steps == 0:
                scaler.unscale_(optimizer)
                torch.nn.utils.clip_grad_norm_(model.parameters(), config.max_grad_norm)
                scaler.step(optimizer)
                scaler.update()
                optimizer.zero_grad()
                scheduler.step()

            if step % config.logging_steps == 0:
                current_lr = scheduler.get_last_lr()[0]
                elapsed = time.time() - epoch_start
                progress = step / len(train_loader)
                eta_seconds = elapsed / max(progress, 1e-9) - elapsed
                print(
                    f"  [Epoch {epoch}/{config.num_epochs}] "
                    f"Step {step}/{len(train_loader)} ({progress * 100:.1f}%) | "
                    f"Loss: {running_loss / step:.4f} | LR: {current_lr:.2e} | "
                    f"Elapsed: {elapsed / 60:.1f}m | ETA: {eta_seconds / 60:.1f}m",
                    flush=True,
                )

        # Epoch Validation
        val_metrics = evaluate_model(model, val_loader, device, config.use_fp16)
        epoch_time = time.time() - epoch_start
        print(f"\n--- Epoch {epoch} Validation ---", flush=True)
        print(f"  Loss: {val_metrics['loss']:.4f} | Acc: {val_metrics['accuracy']:.4f} | F1: {val_metrics['f1']:.4f} | Precision: {val_metrics['precision']:.4f} | Recall: {val_metrics['recall']:.4f} | Time: {epoch_time:.1f}s", flush=True)
        print(f"  Confusion Matrix: TP={val_metrics['tp']}, FP={val_metrics['fp']}, TN={val_metrics['tn']}, FN={val_metrics['fn']}\n", flush=True)

        history.append({
            "epoch": epoch,
            "train_loss": round(running_loss / len(train_loader), 4),
            "val_metrics": val_metrics,
            "epoch_time_seconds": round(epoch_time, 2)
        })

        # Save Best Model
        if val_metrics["f1"] > best_val_f1:
            best_val_f1 = val_metrics["f1"]
            patience_counter = 0
            os.makedirs(os.path.dirname(config.best_model_path), exist_ok=True)
            torch.save({
                "model_state_dict": model.state_dict(),
                "model_config": model_config,
                "training_config": config,
                "val_metrics": val_metrics,
                "epoch": epoch,
                "optimizer_state_dict": optimizer.state_dict(),
                "scheduler_state_dict": scheduler.state_dict(),
            }, config.best_model_path)
            print(f"  [+] New Best Model saved to {config.best_model_path} (Val F1: {best_val_f1:.4f})")
        else:
            patience_counter += 1
            print(f"  [-] No improvement (Patience: {patience_counter}/{config.early_stopping_patience})")
            if patience_counter >= config.early_stopping_patience:
                print(f"  [!] Early stopping triggered at epoch {epoch}.")
                break

    total_training_time = time.time() - start_time
    print("\n" + "=" * 64)
    print(f"  TRAINING COMPLETE (Total Time: {total_training_time/60:.2f} mins)")
    print("=" * 64)

    # Load best checkpoint for final test set evaluation
    checkpoint = torch.load(config.best_model_path, map_location=device, weights_only=False)
    model.load_state_dict(checkpoint["model_state_dict"])
    test_metrics = evaluate_model(model, test_loader, device, config.use_fp16)

    print("\n" + "=" * 64)
    print("  FINAL TEST SET PERFORMANCE (Unseen Data)")
    print(f"  Accuracy:  {test_metrics['accuracy']:.4f}")
    print(f"  Precision: {test_metrics['precision']:.4f}")
    print(f"  Recall:    {test_metrics['recall']:.4f}")
    print(f"  F1-Score:  {test_metrics['f1']:.4f}")
    print(f"  ROC-AUC:   {test_metrics.get('roc_auc', 'N/A')}")
    print(f"  Confusion Matrix: TP={test_metrics['tp']} | FP={test_metrics['fp']} | TN={test_metrics['tn']} | FN={test_metrics['fn']}")
    print("=" * 64)

    results = {
        "best_val_f1": best_val_f1,
        "test_metrics": test_metrics,
        "history": history,
        "training_time_seconds": round(total_training_time, 2)
    }

    # Save results json
    results_path = os.path.join(os.path.dirname(config.best_model_path), "training_history.json")
    with open(results_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train Transformer Secret Detector")
    parser.add_argument("--epochs", type=int, default=3, help="Number of training epochs")
    parser.add_argument("--batch_size", type=int, default=32, help="Batch size")
    parser.add_argument("--lr", type=float, default=2e-5, help="Learning rate")
    parser.add_argument("--gpu_id", type=int, default=None, help="GPU index to use after confirming it is free")
    parser.add_argument("--subset", type=int, default=20000, help="Training subset size")
    parser.add_argument("--val_subset", type=int, default=4000, help="Validation subset size")
    parser.add_argument("--test_subset", type=int, default=4000, help="Test subset size")
    parser.add_argument("--eval_batch_size", type=int, default=64, help="Evaluation batch size")
    parser.add_argument("--max_seq_length", type=int, default=128, help="Maximum token sequence length")
    parser.add_argument("--num_workers", type=int, default=4, help="DataLoader worker count")
    parser.add_argument("--no_fp16", action="store_true", help="Disable FP16")
    parser.add_argument(
        "--output",
        default=None,
        help="Checkpoint path; defaults to the configured production checkpoint",
    )
    parser.add_argument("--resume", default=None, help="Resume model weights from a checkpoint")
    args = parser.parse_args()

    t_cfg = TrainingConfig(
        num_epochs=args.epochs,
        batch_size=args.batch_size,
        learning_rate=args.lr,
        gpu_id=args.gpu_id,
        train_subset_size=args.subset,
        val_subset_size=args.val_subset,
        test_subset_size=args.test_subset,
        eval_batch_size=args.eval_batch_size,
        max_seq_length=args.max_seq_length,
        num_workers=args.num_workers,
        use_fp16=not args.no_fp16,
        best_model_path=args.output or TrainingConfig().best_model_path,
    )
    m_cfg = ModelConfig()
    train_transformer(t_cfg, m_cfg, resume_path=args.resume)
