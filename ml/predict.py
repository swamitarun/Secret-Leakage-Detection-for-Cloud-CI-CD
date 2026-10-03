"""
ML Predict — uses the trained Random Forest model to predict risk levels
for new scanner findings, or for batch prediction from metadata CSV.
"""

import os
import joblib
import pandas as pd
import numpy as np

MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "reports")
MODEL_PATH = os.path.join(MODEL_DIR, "risk_classifier.joblib")
ENCODER_PATH = os.path.join(MODEL_DIR, "label_encoders.joblib")

CATEGORICAL_COLS = ["file_type", "secret_type", "iac_type", "cloud_provider"]
BINARY_COLS = ["secret_detected", "ci_cd_context"]


def load_model():
    """Load the trained model and encoders."""
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(
            f"Model not found at {MODEL_PATH}. Run train.py first."
        )
    clf = joblib.load(MODEL_PATH)
    meta = joblib.load(ENCODER_PATH)
    return clf, meta["label_encoder"], meta["feature_columns"]


def predict_single(
    file_type: str,
    secret_type: str,
    secret_detected: bool,
    iac_type: str,
    cloud_provider: str,
    ci_cd_context: bool,
    entropy: float,
    content_length: int,
) -> tuple[str, dict[str, float]]:
    """
    Predict risk level for a single sample.

    Returns (predicted_label, probability_dict).
    """
    clf, le, feature_cols = load_model()

    row = {
        "file_type": file_type,
        "secret_type": secret_type,
        "secret_detected": int(secret_detected),
        "iac_type": iac_type,
        "cloud_provider": cloud_provider,
        "ci_cd_context": int(ci_cd_context),
        "entropy": entropy,
        "content_length": content_length,
    }

    df = pd.DataFrame([row])
    df = pd.get_dummies(df, columns=CATEGORICAL_COLS, drop_first=False)

    # Align columns with training set
    for col in feature_cols:
        if col not in df.columns:
            df[col] = 0
    df = df[feature_cols]

    pred = clf.predict(df)[0]
    proba = clf.predict_proba(df)[0]
    label = le.inverse_transform([pred])[0]

    prob_dict = {le.inverse_transform([i])[0]: round(float(p), 4)
                 for i, p in enumerate(proba)}

    return label, prob_dict


def predict_batch(csv_path: str) -> pd.DataFrame:
    """Predict risk levels for all samples in a metadata CSV."""
    clf, le, feature_cols = load_model()

    df = pd.read_csv(csv_path)
    df_encoded = pd.get_dummies(df, columns=CATEGORICAL_COLS, drop_first=False)
    for col in BINARY_COLS:
        if col in df_encoded.columns:
            df_encoded[col] = df_encoded[col].astype(int)

    drop_cols = ["risk_level", "sample_id", "filename", "aws_resource"]
    drop_cols = [c for c in drop_cols if c in df_encoded.columns]
    X = df_encoded.drop(columns=drop_cols)

    for col in feature_cols:
        if col not in X.columns:
            X[col] = 0
    X = X[feature_cols]

    preds = clf.predict(X)
    df["predicted_risk_level"] = le.inverse_transform(preds)

    return df


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Predict risk levels")
    parser.add_argument("csv_path", help="Path to metadata CSV")
    parser.add_argument("-o", "--output", default=None, help="Output CSV path")
    args = parser.parse_args()

    result = predict_batch(args.csv_path)
    out = args.output or args.csv_path.replace(".csv", "_predictions.csv")
    result.to_csv(out, index=False)
    print(f"[+] Predictions saved to {out}")

    # Show accuracy if ground truth available
    if "risk_level" in result.columns:
        from sklearn.metrics import accuracy_score
        acc = accuracy_score(result["risk_level"], result["predicted_risk_level"])
        print(f"[+] Accuracy vs ground truth: {acc:.4f}")
