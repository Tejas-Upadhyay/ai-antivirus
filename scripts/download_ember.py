#!/usr/bin/env python3
"""
Download EMBER 2018 dataset.
Dataset source: https://github.com/elastic/ember
Files hosted on S3: https://ember-dataset.s3.amazonaws.com/
"""
import argparse
import os
import sys
import tarfile
import urllib.request
from pathlib import Path
from tqdm import tqdm


EMBER_URLS = {
    "train_features.jsonl": "https://ember-dataset.s3.amazonaws.com/train_features.jsonl",
    "train_labels.csv": "https://ember-dataset.s3.amazonaws.com/train_labels.csv",
    "test_features.jsonl": "https://ember-dataset.s3.amazonaws.com/test_features.jsonl",
    "test_labels.csv": "https://ember-dataset.s3.amazonaws.com/test_labels.csv",
}


class DownloadProgressBar(tqdm):
    def update_to(self, b=1, bsize=1, tsize=None):
        if tsize is not None:
            self.total = tsize
        self.update(b * bsize - self.n)


def download_file(url: str, output_path: Path):
    """Download file with progress bar."""
    print(f"Downloading {url} -> {output_path}")
    with DownloadProgressBar(unit='B', unit_scale=True, miniters=1, desc=output_path.name) as t:
        urllib.request.urlretrieve(url, output_path, reporthook=t.update_to)


def main():
    parser = argparse.ArgumentParser(description="Download EMBER 2018 dataset")
    parser.add_argument('--output-dir', type=Path, default=Path('data/ember2018'))
    parser.add_argument('--files', nargs='+', choices=list(EMBER_URLS.keys()) + ['all'],
                        default=['all'], help='Files to download')
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)

    files_to_download = list(EMBER_URLS.keys()) if 'all' in args.files else args.files

    for fname in files_to_download:
        url = EMBER_URLS[fname]
        output_path = args.output_dir / fname
        if output_path.exists():
            print(f"Skipping {fname} (already exists)")
            continue
        try:
            download_file(url, output_path)
        except Exception as e:
            print(f"Error downloading {fname}: {e}")
            sys.exit(1)

    print(f"\nDone! Dataset downloaded to {args.output_dir}")
    print("Run training with:")
    print(f"  python scripts/train_ember_lgbm.py --data-dir {args.output_dir}")


if __name__ == '__main__':
    main()