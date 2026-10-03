"""
ML Risk Classifier — trains a lightweight Random Forest model on the
synthetic dataset metadata to predict risk_level.

Features used:
  - file_type          (one-hot encoded)
  - secret_type        (one-hot encoded)
  - secret_detected    (binary)
  - iac_type           (one-hot encoded)
  - cloud_provider     (one-hot encoded)
  - ci_cd_context      (binary)
  - entropy            (continuous)
  - content_length     (continuous)

Target: risk_level  (SAFE / LOW / HIGH / CRITICAL)

Uses scikit-learn only — no deep learning.
"""

import os
import sys
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    f1_score,
)
from sklearn.preprocessing import LabelEncoder


MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "reports")
MODEL_PATH = os.path.join(MODEL_DIR, "risk_classifier.joblib")
ENCODER_PATH = os.path.join(MODEL_DIR, "label_encoders.joblib")
RESULTS_PATH = os.path.join(MODEL_DIR, "evaluation_results.json")

# Categorical columns to one-hot encode
CATEGORICAL_COLS = ["file_type", "secret_type", "iac_type", "cloud_provider"]
BINARY_COLS = ["secret_detected", "ci_cd_context"]
NUMERIC_COLS = ["entropy", "content_length"]
TARGET_COL = "risk_level"


def load_and_prepare(csv_path: str) -> tuple[pd.DataFrame, pd.Series]:
    """Load metadata CSV and prepare feature matrix + target vector."""
    df = pd.read_csv(csv_path)

    # One-hot encode categoricals
    df_encoded = pd.get_dummies(df, columns=CATEGORICAL_COLS, drop_first=False)

    # Convert booleans to int
    for col in BINARY_COLS:
        if col in df_encoded.columns:
            df_encoded[col] = df_encoded[col].astype(int)

    # Separate features / target
    drop_cols = [TARGET_COL, "sample_id", "filename", "aws_resource"]
    drop_cols = [c for c in drop_cols if c in df_encoded.columns]
    X = df_encoded.drop(columns=drop_cols)
    y = df[TARGET_COL]

    return X, y


def train(csv_path: str, test_size: float = 0.2, random_state: int = 42) -> dict:
    """
    Train Random Forest risk classifier.

    Returns a dict with evaluation metrics (actual measured, not invented).
    """
    print(f"[*] Loading data from {csv_path}")
    X, y = load_and_prepare(csv_path)
    print(f"[*] Dataset: {len(X)} samples, {X.shape[1]} features")
    print(f"[*] Class distribution:\n{y.value_counts().to_string()}\n")

    # Encode labels
    le = LabelEncoder()
    y_encoded = le.fit_transform(y)

    # Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_encoded, test_size=test_size, random_state=random_state,
        stratify=y_encoded,
    )

    # Train
    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        random_state=random_state,
        class_weight="balanced",
        n_jobs=-1,
    )
    print("[*] Training Random Forest classifier...")
    clf.fit(X_train, y_train)

    # Evaluate
    y_pred = clf.predict(X_test)
    y_pred_labels = le.inverse_transform(y_pred)
    y_test_labels = le.inverse_transform(y_test)

    acc = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred, average="weighted")
    report = classification_report(y_test_labels, y_pred_labels, output_dict=True)
    cm = confusion_matrix(y_test_labels, y_pred_labels, labels=le.classes_).tolist()

    # Cross-validation
    cv_scores = cross_val_score(clf, X, y_encoded, cv=5, scoring="accuracy")

    results = {
        "accuracy": round(acc, 4),
        "f1_weighted": round(f1, 4),
        "cv_accuracy_mean": round(cv_scores.mean(), 4),
        "cv_accuracy_std": round(cv_scores.std(), 4),
        "classification_report": report,
        "confusion_matrix": cm,
        "classes": le.classes_.tolist(),
        "n_train": len(X_train),
        "n_test": len(X_test),
        "n_features": X.shape[1],
    }

    # Print results
    print(f"\n{'='*50}")
    print(f"  EVALUATION RESULTS  (actual measured)")
    print(f"{'='*50}")
    print(f"  Accuracy:       {acc:.4f}")
    print(f"  F1 (weighted):  {f1:.4f}")
    print(f"  CV Accuracy:    {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")
    print(f"\n  Classification Report:")
    print(classification_report(y_test_labels, y_pred_labels))
    print(f"  Confusion Matrix:")
    print(f"  Classes: {le.classes_.tolist()}")
    for row in cm:
        print(f"    {row}")
    print(f"{'='*50}")

    # Feature importance
    importances = clf.feature_importances_
    feature_names = X.columns.tolist()
    top_features = sorted(zip(feature_names, importances), key=lambda x: x[1], reverse=True)[:10]
    print("\n  Top 10 Important Features:")
    for fname, imp in top_features:
        print(f"    {fname:40s} {imp:.4f}")
    results["top_features"] = {k: round(v, 4) for k, v in top_features}

    # Save model & results
    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(clf, MODEL_PATH)
    joblib.dump({"label_encoder": le, "feature_columns": X.columns.tolist()}, ENCODER_PATH)
    with open(RESULTS_PATH, "w") as f:
        # Convert numpy types for JSON
        json.dump(results, f, indent=2, default=str)

    print(f"\n[+] Model saved to {MODEL_PATH}")
    print(f"[+] Results saved to {RESULTS_PATH}")

    return results


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Train risk classifier")
    parser.add_argument("csv_path", help="Path to metadata CSV")
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    train(args.csv_path, test_size=args.test_size, random_state=args.seed)
