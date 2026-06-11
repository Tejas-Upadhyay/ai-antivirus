#!/usr/bin/env python3
"""
Inference script for trained malware classifier.
Usage: python scripts/infer.py --model models/ember_lgbm.pkl --file suspicious.exe
"""
import argparse
import joblib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from static.ember_features import extract_ember_features


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--model', type=Path, default=Path('models/ember_lgbm.pkl'))
    parser.add_argument('--file', type=Path, required=True, help='PE file to analyze')
    parser.add_argument('--threshold', type=float, default=0.5)
    args = parser.parse_args()

    if not args.model.exists():
        print(f"Model not found: {args.model}")
        sys.exit(1)

    if not args.file.exists():
        print(f"File not found: {args.file}")
        sys.exit(1)

    print(f"Loading model from {args.model}...")
    model = joblib.load(args.model)

    print(f"Extracting features from {args.file}...")
    try:
        features = extract_ember_features(str(args.file))
    except Exception as e:
        print(f"Feature extraction failed: {e}")
        sys.exit(1)

    print("Running inference...")
    if hasattr(model, 'predict_proba'):
        score = model.predict_proba([features])[0, 1]
    else:
        score = model.predict([features], num_iteration=model.best_iteration)[0]

    print(f"\n{'='*50}")
    print(f"File: {args.file}")
    print(f"Malicious probability: {score:.4f}")
    print(f"Threshold: {args.threshold}")
    print(f"Verdict: {'MALICIOUS' if score >= args.threshold else 'BENIGN'}")
    print(f"{'='*50}")


if __name__ == '__main__':
    main()