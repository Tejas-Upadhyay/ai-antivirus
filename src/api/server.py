"""
FastAPI inference server for malware detection.
Combines ML model + YARA rules.
"""
import joblib
import numpy as np
from pathlib import Path
from typing import Optional, List
from contextlib import asynccontextmanager

from fastapi import FastAPI, File, UploadFile, HTTPException, Form
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import uvicorn

# Local imports
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from src.static.ember_features import extract_ember_features
from src.rules.scanner import YaraScanner, format_yara_results, YaraMatch


# Global state
model = None
yara_scanner = None
model_path = None
feature_names = None


class ScanResponse(BaseModel):
    filename: str
    sha256: str
    size: int
    ml_score: float = Field(..., description="Malicious probability [0,1]")
    ml_verdict: str = Field(..., description="BENIGN or MALICIOUS")
    yara_matches: List[dict] = Field(default_factory=list)
    yara_summary: str = ""
    threshold: float


class HealthResponse(BaseModel):
    status: str
    model_loaded: bool
    yara_loaded: bool
    model_path: Optional[str]


@asynccontextmanager
async def lifespan(app: FastAPI):
    global model, yara_scanner, model_path, feature_names

    # Load model
    default_model = Path(__file__).parent.parent.parent / "models" / "ember_lgbm.pkl"
    if default_model.exists():
        model = joblib.load(default_model)
        model_path = str(default_model)
        print(f"Loaded model from {default_model}")
    else:
        print(f"Warning: Model not found at {default_model}")

    # Load feature names
    feat_path = default_model.with_suffix('.features.pkl')
    if feat_path.exists():
        feature_names = joblib.load(feat_path)

    # Load YARA rules
    rules_dir = Path(__file__).parent.parent / "rules"
    yara_scanner = YaraScanner(rules_dir)

    yield

    # Cleanup
    model = None
    yara_scanner = None


app = FastAPI(
    title="AI Antivirus API",
    description="ML + YARA malware detection",
    version="0.1.0",
    lifespan=lifespan
)


@app.get("/health", response_model=HealthResponse)
async def health():
    return HealthResponse(
        status="ok",
        model_loaded=model is not None,
        yara_loaded=yara_scanner is not None and yara_scanner.compiled_rules is not None,
        model_path=model_path
    )


@app.post("/scan", response_model=ScanResponse)
async def scan_file(
    file: UploadFile = File(...),
    threshold: float = Form(0.5)
):
    if not model:
        raise HTTPException(503, "Model not loaded")

    # Read file
    content = await file.read()
    size = len(content)

    if size == 0:
        raise HTTPException(400, "Empty file")

    # Compute SHA256
    import hashlib
    sha256 = hashlib.sha256(content).hexdigest()

    # ML inference
    try:
        features = extract_ember_features_from_bytes(content)
        if hasattr(model, 'predict_proba'):
            ml_score = float(model.predict_proba([features])[0, 1])
        else:
            ml_score = float(model.predict([features], num_iteration=model.best_iteration)[0])
    except Exception as e:
        raise HTTPException(500, f"Feature extraction failed: {e}")

    ml_verdict = "MALICIOUS" if ml_score >= threshold else "BENIGN"

    # YARA scan
    yara_matches = []
    yara_summary = ""
    if yara_scanner and yara_scanner.compiled_rules:
        matches = yara_scanner.scan_bytes(content)
        yara_matches = [
            {
                "rule": m.rule_name,
                "severity": m.meta.get('severity', 'unknown'),
                "description": m.meta.get('description', ''),
                "tags": m.tags,
                "strings_matched": len(m.strings)
            }
            for m in matches
        ]
        yara_summary = format_yara_results(matches)

    return ScanResponse(
        filename=file.filename or "unknown",
        sha256=sha256,
        size=size,
        ml_score=ml_score,
        ml_verdict=ml_verdict,
        yara_matches=yara_matches,
        yara_summary=yara_summary,
        threshold=threshold
    )


@app.post("/scan/features", response_model=ScanResponse)
async def scan_features(
    features: List[float],
    threshold: float = Form(0.5),
    filename: str = Form("feature_vector"),
    sha256: str = Form(""),
    size: int = Form(0)
):
    """Scan using pre-extracted features (for integration with other tools)."""
    if not model:
        raise HTTPException(503, "Model not loaded")

    if len(features) != 2381:
        raise HTTPException(400, f"Expected 2381 features, got {len(features)}")

    if hasattr(model, 'predict_proba'):
        ml_score = float(model.predict_proba([features])[0, 1])
    else:
        ml_score = float(model.predict([features], num_iteration=model.best_iteration)[0])

    ml_verdict = "MALICIOUS" if ml_score >= threshold else "BENIGN"

    return ScanResponse(
        filename=filename,
        sha256=sha256 or "unknown",
        size=size,
        ml_score=ml_score,
        ml_verdict=ml_verdict,
        yara_matches=[],
        yara_summary="Feature-only scan (no YARA)",
        threshold=threshold
    )


def extract_ember_features_from_bytes(data: bytes) -> np.ndarray:
    """Extract EMBER features from raw bytes without writing to disk."""
    import tempfile
    import os

    # Write to temp file for feature extraction
    with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
        f.write(data)
        temp_path = f.name

    try:
        features = extract_ember_features(temp_path)
    finally:
        os.unlink(temp_path)

    return features


def main():
    """Run the server."""
    uvicorn.run(
        "src.api.server:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
        workers=1
    )


if __name__ == "__main__":
    main()