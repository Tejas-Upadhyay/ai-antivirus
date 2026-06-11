#!/usr/bin/env python3
"""
Train baseline on EMBER features (LightGBM or sklearn fallback).
Usage: python scripts/train_ember_lgbm.py --data-dir /path/to/ember2018 --output models/ember_lgbm.txt
"""
import argparse
import numpy as np
import pandas as pd
from pathlib import Path
import json
import joblib
import sys
from sklearn.model_selection import train_test_split
from sklearn.metrics import roc_auc_score, classification_report
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.calibration import CalibratedClassifierCV

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from static.ember_features import extract_ember_features

try:
    import lightgbm as lgb
    HAS_LGBM = True
except (ImportError, OSError):
    HAS_LGBM = False
    print("LightGBM not available, using sklearn GradientBoostingClassifier")


def load_ember_dataset(data_dir: Path, max_samples: int = None):
    """Load EMBER 2018 dataset from JSONL files (supports both old and new format)."""
    X_list = []
    y_list = []

    # Try new format first: train_features.jsonl + train_labels.csv
    features_path = data_dir / "train_features.jsonl"
    labels_path = data_dir / "train_labels.csv"

    if features_path.exists() and labels_path.exists():
        print(f"Loading {features_path} and {labels_path}...")
        # Load labels into dict
        labels_df = pd.read_csv(labels_path)
        label_map = dict(zip(labels_df['sha256'], labels_df['label']))

        with open(features_path) as f:
            for i, line in enumerate(f):
                if max_samples and i >= max_samples:
                    break
                try:
                    record = json.loads(line)
                    sha256 = record.get('sha256', '')
                    if sha256 in label_map:
                        X_list.append(record['feature'])
                        y_list.append(label_map[sha256])
                except Exception as e:
                    print(f"Error parsing line {i}: {e}")

        return np.array(X_list), np.array(y_list)

    # Fallback to old format: benign.jsonl + malicious.jsonl
    for label, fname in [(0, "benign.jsonl"), (1, "malicious.jsonl")]:
        fpath = data_dir / fname
        if not fpath.exists():
            print(f"Warning: {fpath} not found")
            continue

        print(f"Loading {fname}...")
        with open(fpath) as f:
            for i, line in enumerate(f):
                if max_samples and i >= max_samples // 2:
                    break
                try:
                    record = json.loads(line)
                    if 'feature' in record:
                        X_list.append(record['feature'])
                    y_list.append(label)
                except Exception as e:
                    print(f"Error parsing line {i}: {e}")

    return np.array(X_list), np.array(y_list)


def train_lgbm(X_train, y_train, X_val, y_val, params: dict):
    """Train LightGBM with early stopping."""
    if not HAS_LGBM:
        raise RuntimeError("LightGBM not available")

    train_data = lgb.Dataset(X_train, label=y_train)
    val_data = lgb.Dataset(X_val, label=y_val, reference=train_data)

    model = lgb.train(
        params,
        train_data,
        num_boost_round=params.get('n_estimators', 2000),
        valid_sets=[train_data, val_data],
        valid_names=['train', 'val'],
        callbacks=[
            lgb.early_stopping(stopping_rounds=100),
            lgb.log_evaluation(period=50)
        ]
    )
    return model


def train_sklearn_gbm(X_train, y_train, X_val, y_val, params: dict):
    """Train sklearn GradientBoostingClassifier with calibration."""
    n_estimators = params.get('n_estimators', 500)
    learning_rate = params.get('learning_rate', 0.05)
    max_depth = 6

    base_model = GradientBoostingClassifier(
        n_estimators=n_estimators,
        learning_rate=learning_rate,
        max_depth=max_depth,
        subsample=0.8,
        random_state=42,
        verbose=1
    )

    # Calibrate probabilities
    model = CalibratedClassifierCV(base_model, method='isotonic', cv='prefit')
    base_model.fit(X_train, y_train)
    model.fit(X_val, y_val)

    return model


def evaluate_model(model, X_test, y_test):
    """Evaluate model and print metrics."""
    if HAS_LGBM and hasattr(model, 'best_iteration'):
        y_pred = model.predict(X_test, num_iteration=model.best_iteration)
    elif hasattr(model, 'predict_proba'):
        y_pred = model.predict_proba(X_test)[:, 1]
    else:
        y_pred = model.predict(X_test)

    auc = roc_auc_score(y_test, y_pred)
    print(f"\nTest AUC: {auc:.4f}")

    y_pred_binary = (y_pred > 0.5).astype(int)
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred_binary, target_names=['Benign', 'Malicious']))

    return auc


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--data-dir', type=Path, required=True, help='Path to EMBER 2018 directory')
    parser.add_argument('--output', type=Path, default=Path('models/ember_lgbm.txt'))
    parser.add_argument('--max-samples', type=int, default=None, help='Max samples per class for quick testing')
    parser.add_argument('--test-size', type=float, default=0.2)
    parser.add_argument('--seed', type=int, default=42)
    args = parser.parse_args()

    args.output.parent.mkdir(parents=True, exist_ok=True)

    print("Loading EMBER dataset...")
    X, y = load_ember_dataset(args.data_dir, args.max_samples)
    print(f"Loaded {len(X)} samples ({np.sum(y)} malicious, {len(y)-np.sum(y)} benign)")

    # Temporal split: first 80% train, last 20% test (assuming data is time-sorted)
    split_idx = int(len(X) * (1 - args.test_size))
    X_train, X_test = X[:split_idx], X[split_idx:]
    y_train, y_test = y[:split_idx], y[split_idx:]

    # Further split train into train/val
    X_train, X_val, y_train, y_val = train_test_split(
        X_train, y_train, test_size=0.1, random_state=args.seed, stratify=y_train
    )

    print(f"Train: {len(X_train)}, Val: {len(X_val)}, Test: {len(X_test)}")

    # Load params from config
    import yaml
    with open(Path(__file__).parent.parent / 'configs/model.yaml') as f:
        config = yaml.safe_load(f)

    params = config['static']['ember_lgbm']
    params['n_estimators'] = 500 if not HAS_LGBM else 2000
    if 'verbosity' in params:
        del params['verbosity']

    if HAS_LGBM:
        print("\nTraining LightGBM...")
        model = train_lgbm(X_train, y_train, X_val, y_val, params)
    else:
        print("\nTraining sklearn GradientBoostingClassifier (fallback)...")
        model = train_sklearn_gbm(X_train, y_train, X_val, y_val, params)

    print("\nEvaluating...")
    auc = evaluate_model(model, X_test, y_test)

    print(f"\nSaving model to {args.output}")
    if HAS_LGBM and hasattr(model, 'save_model'):
        model.save_model(str(args.output))
    else:
        joblib.dump(model, args.output.with_suffix('.pkl'))

    # Save feature names
    feature_names = [f"feat_{i}" for i in range(X.shape[1])]
    joblib.dump(feature_names, args.output.with_suffix('.features.pkl'))

    print("Done!")


if __name__ == '__main__':
    main()