#!/usr/bin/env python3
"""
Unified malware scanner: ML model + YARA rules.
Usage: python scripts/scan.py suspicious.exe [--threshold 0.5] [--json]
"""
import argparse
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from static.ember_features import extract_ember_features
from rules.scanner import YaraScanner, format_yara_results
import joblib


def load_model(model_path: Path):
    if not model_path.exists():
        print(f"Model not found: {model_path}")
        return None
    return joblib.load(model_path)


def scan_file(filepath: Path, model, yara_scanner: YaraScanner, threshold: float = 0.5) -> dict:
    """Scan a single file."""
    if not filepath.exists():
        return {"error": f"File not found: {filepath}"}

    # Read file for hash
    with open(filepath, 'rb') as f:
        content = f.read()

    sha256 = hashlib.sha256(content).hexdigest()
    size = len(content)

    # ML inference
    ml_score = 0.0
    ml_error = None
    try:
        features = extract_ember_features(str(filepath))
        if hasattr(model, 'predict_proba'):
            ml_score = float(model.predict_proba([features])[0, 1])
        else:
            ml_score = float(model.predict([features], num_iteration=model.best_iteration)[0])
    except Exception as e:
        ml_error = str(e)

    ml_verdict = "MALICIOUS" if ml_score >= threshold else "BENIGN"

    # YARA scan
    yara_matches = []
    yara_summary = ""
    if yara_scanner and yara_scanner.compiled_rules:
        matches = yara_scanner.scan_file(filepath)
        yara_matches = [
            {
                "rule": m.rule_name,
                "severity": m.meta.get('severity', 'unknown'),
                "description": m.meta.get('description', ''),
                "tags": m.tags,
                "strings_matched": len(m.strings),
                "matched_strings": [
                    {
                        "identifier": s['identifier'],
                        "offset": s['offset'],
                        "data": s['matched_data'].decode('ascii', errors='replace')[:100]
                    }
                    for s in m.strings[:5]
                ]
            }
            for m in matches
        ]
        yara_summary = format_yara_results(matches)

    return {
        "file": str(filepath),
        "sha256": sha256,
        "size": size,
        "ml": {
            "score": ml_score,
            "verdict": ml_verdict,
            "threshold": threshold,
            "error": ml_error
        },
        "yara": {
            "matches": yara_matches,
            "summary": yara_summary
        }
    }


def scan_directory(dirpath: Path, model, yara_scanner: YaraScanner, threshold: float, recursive: bool) -> list:
    """Scan all files in a directory."""
    results = []
    pattern = "**/*" if recursive else "*"
    for filepath in dirpath.glob(pattern):
        if filepath.is_file():
            # Skip obvious non-executables
            if filepath.suffix.lower() in ['.txt', '.log', '.md', '.json', '.csv', '.xml', '.yaml', '.yml']:
                continue
            result = scan_file(filepath, model, yara_scanner, threshold)
            results.append(result)
    return results


def main():
    parser = argparse.ArgumentParser(description="AI Antivirus Scanner")
    parser.add_argument('target', type=Path, help='File or directory to scan')
    parser.add_argument('--model', type=Path, default=Path('models/ember_lgbm.pkl'), help='Model path')
    parser.add_argument('--threshold', type=float, default=0.5, help='Malicious threshold')
    parser.add_argument('--recursive', '-r', action='store_true', help='Recursive directory scan')
    parser.add_argument('--json', action='store_true', help='Output JSON')
    parser.add_argument('--rules-dir', type=Path, default=Path('src/rules'), help='YARA rules directory')
    args = parser.parse_args()

    # Load model
    model = load_model(args.model)
    if not model:
        sys.exit(1)

    # Load YARA
    yara_scanner = YaraScanner(args.rules_dir)

    # Scan
    if args.target.is_file():
        results = [scan_file(args.target, model, yara_scanner, args.threshold)]
    elif args.target.is_dir():
        results = scan_directory(args.target, model, yara_scanner, args.threshold, args.recursive)
    else:
        print(f"Error: {args.target} is not a file or directory")
        sys.exit(1)

    # Output
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            if "error" in r:
                print(f"❌ {r['error']}")
                continue

            ml = r['ml']
            yara = r['yara']

            verdict_icon = "🔴" if ml['verdict'] == "MALICIOUS" else "🟢"
            print(f"\n{verdict_icon} {r['file']}")
            print(f"   SHA256: {r['sha256']}")
            print(f"   Size: {r['size']:,} bytes")
            print(f"   ML Score: {ml['score']:.4f} (threshold: {ml['threshold']}) -> {ml['verdict']}")
            if ml['error']:
                print(f"   ML Error: {ml['error']}")

            if yara['matches']:
                print(f"   YARA: {len(yara['matches'])} rule(s) matched")
                for m in yara['matches']:
                    sev = m['severity'].upper()
                    print(f"     [{sev}] {m['rule']}: {m['description']}")
            else:
                print(f"   YARA: No matches")


if __name__ == '__main__':
    main()