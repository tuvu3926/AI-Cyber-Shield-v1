"""Retrain the Naive Bayes model with scaled URL features.

Expected input: a CSV containing all columns from services.feature_extractor.FEATURE_NAMES
and one label column. Labels may be numeric or text values such as phishing,
legitimate, safe, malicious, or benign.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import joblib
import pandas as pd
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import GaussianNB
from sklearn.preprocessing import MinMaxScaler

from config import Config
from services.feature_extractor import FEATURE_NAMES


LABEL_MAP = {
    "phishing": Config.PHISHING_LABEL,
    "malicious": Config.PHISHING_LABEL,
    "bad": Config.PHISHING_LABEL,
    "legitimate": Config.LEGITIMATE_LABEL,
    "benign": Config.LEGITIMATE_LABEL,
    "safe": Config.LEGITIMATE_LABEL,
    "good": Config.LEGITIMATE_LABEL,
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train scaled Gaussian Naive Bayes URL model.")
    parser.add_argument("--data", required=True, type=Path, help="Training CSV path.")
    parser.add_argument("--label-column", default="label", help="Target label column name.")
    parser.add_argument("--output", default=Config.NB_MODEL_FILE, type=Path, help="Output .pkl path.")
    parser.add_argument("--test-size", default=0.2, type=float, help="Held-out test split fraction.")
    parser.add_argument("--random-state", default=42, type=int, help="Train/test split seed.")
    return parser.parse_args()


def normalize_labels(series: pd.Series) -> pd.Series:
    if pd.api.types.is_numeric_dtype(series):
        return series.astype(int)
    normalized = series.astype(str).str.strip().str.lower()
    unknown = sorted(set(normalized) - set(LABEL_MAP))
    if unknown:
        raise ValueError(f"Unknown label values: {unknown}")
    return normalized.map(LABEL_MAP).astype(int)


def main() -> None:
    args = parse_args()
    frame = pd.read_csv(args.data)

    missing_features = [name for name in FEATURE_NAMES if name not in frame.columns]
    if missing_features:
        raise RuntimeError(f"Training data is missing feature columns: {missing_features}")
    if args.label_column not in frame.columns:
        raise RuntimeError(f"Training data is missing label column: {args.label_column}")

    x = frame[FEATURE_NAMES].apply(pd.to_numeric, errors="raise")
    y = normalize_labels(frame[args.label_column])

    x_train, x_test, y_train, y_test = train_test_split(
        x,
        y,
        test_size=args.test_size,
        random_state=args.random_state,
        stratify=y,
    )

    scaler = MinMaxScaler()
    x_train_scaled = scaler.fit_transform(x_train)
    x_test_scaled = scaler.transform(x_test)

    model = GaussianNB()
    model.fit(x_train_scaled, y_train)

    predictions = model.predict(x_test_scaled)
    print(f"Accuracy: {accuracy_score(y_test, predictions):.4f}")
    print("Confusion matrix:")
    print(confusion_matrix(y_test, predictions, labels=[Config.PHISHING_LABEL, Config.LEGITIMATE_LABEL]))
    print("Classification report:")
    print(classification_report(y_test, predictions, digits=4))

    args.output.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {
            "model": model,
            "scaler": scaler,
            "feature_columns": list(FEATURE_NAMES),
        },
        args.output,
    )
    print(f"Saved scaled Naive Bayes bundle to {args.output}")


if __name__ == "__main__":
    main()
