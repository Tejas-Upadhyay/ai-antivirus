#!/usr/bin/env python3
"""
Create synthetic EMBER-like data for pipeline testing.
This is NOT for real training - just to verify the pipeline works.
"""
import numpy as np
import json
import pandas as pd
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from static.ember_features import EmberFeatureExtractor


def create_synthetic_ember_data(output_dir: Path, n_samples: int = 1000):
    """Create synthetic feature vectors matching EMBER format."""
    output_dir.mkdir(parents=True, exist_ok=True)

    # EMBER feature vector is 2381 dimensions
    feature_dim = 2381

    print(f"Generating {n_samples} synthetic samples ({feature_dim} features each)...")

    # Generate features with some class separation
    n_malicious = n_samples // 2
    n_benign = n_samples - n_malicious

    # Benign: centered around 0, lower variance
    benign_features = np.random.normal(0, 0.5, (n_benign, feature_dim)).astype(np.float32)
    # Malicious: shifted mean, higher variance in some features
    malicious_features = np.random.normal(0.3, 0.8, (n_malicious, feature_dim)).astype(np.float32)

    # Add some discriminative features (imports, strings, entropy)
    # Import features (indices ~200-1500): malicious has more suspicious imports
    malicious_features[:, 200:1500] += np.random.exponential(0.5, (n_malicious, 1300))
    benign_features[:, 200:1500] += np.random.exponential(0.1, (n_benign, 1300))

    # Byte entropy histogram (last 256): malicious has higher entropy
    malicious_features[:, -256:] += np.random.gamma(2, 0.5, (n_malicious, 256))
    benign_features[:, -256:] += np.random.gamma(1, 0.3, (n_benign, 256))

    X = np.vstack([benign_features, malicious_features])
    y = np.hstack([np.zeros(n_benign), np.ones(n_malicious)])

    # Shuffle
    idx = np.random.permutation(n_samples)
    X, y = X[idx], y[idx]

    # Save as JSONL (matching EMBER format)
    features_path = output_dir / "train_features.jsonl"
    labels_path = output_dir / "train_labels.csv"

    print(f"Writing {features_path}...")
    with open(features_path, 'w') as f:
        for i, feat_vec in enumerate(X):
            record = {"sha256": f"synthetic_{i:08x}", "feature": feat_vec.tolist()}
            f.write(json.dumps(record) + "\n")

    print(f"Writing {labels_path}...")
    df = pd.DataFrame({"sha256": [f"synthetic_{i:08x}" for i in range(n_samples)], "label": y.astype(int)})
    df.to_csv(labels_path, index=False)

    # Also create test split
    test_X = np.random.normal(0, 0.5, (200, feature_dim)).astype(np.float32)
    test_y = np.random.randint(0, 2, 200)

    with open(output_dir / "test_features.jsonl", 'w') as f:
        for i, feat_vec in enumerate(test_X):
            record = {"sha256": f"test_{i:08x}", "feature": feat_vec.tolist()}
            f.write(json.dumps(record) + "\n")

    pd.DataFrame({"sha256": [f"test_{i:08x}" for i in range(200)], "label": test_y}).to_csv(
        output_dir / "test_labels.csv", index=False
    )

    print(f"Done! Created synthetic dataset in {output_dir}")
    print(f"  Train: {n_samples} samples ({n_malicious} malicious, {n_benign} benign)")
    print(f"  Test: 200 samples")


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--output-dir', type=Path, default=Path('data/ember2018'))
    parser.add_argument('--n-samples', type=int, default=2000)
    args = parser.parse_args()
    create_synthetic_ember_data(args.output_dir, args.n_samples)