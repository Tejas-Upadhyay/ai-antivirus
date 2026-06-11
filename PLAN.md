# AI Antivirus Architecture Plan

## Core Detection Layers

### 1. Static Analysis (Pre-execution)
- **PE/ELF Feature Extraction**: imports, sections, entropy, strings, metadata
- **Byte n-grams / CNN on raw bytes**: MalConv-style models
- **Control Flow Graph embeddings**: graph neural networks on function call graphs
- **String/URL/IP indicators**: transformer on extracted strings

### 2. Dynamic Analysis (Sandbox)
- **API call sequences**: LSTM/Transformer on syscall traces
- **Behavioral graphs**: process tree, file/registry/network activity
- **Memory dump analysis**: heuristic + ML on injected code

### 3. Heuristic/Rule Engine (Explainable)
- YARA-style rules with ML-assisted rule generation
- MITRE ATT&CK technique mapping

## ML Pipeline

```
Training Data → Feature Engineering → Model Training → Calibration → Deployment
     ↑              ↑                    ↑              ↑            ↑
  MalwareBazaar   PE headers,          MalConv,       Temperature   ONNX/TensorRT
  VirusTotal      CFG, strings,        GraphSAGE,     scaling,      + quantization
  Internal sandbox API sequences      BERT on strings   conformal    for edge
```

## Key Technical Decisions

| Component | Recommendation |
|-----------|----------------|
| **Static model** | MalConv2 / EMBER-style LightGBM on 2K features |
| **Dynamic model** | Transformer on syscall n-grams (window=64) |
| **Ensemble** | Stacking with calibrated probabilities |
| **False positive control** | Conformal prediction + cost-sensitive thresholds |
| **Updates** | Continual learning with replay buffer; weekly retrain |

## Infrastructure

- **Feature store**: Feast or custom Parquet/Arrow pipeline
- **Training**: PyTorch + Lightning, distributed on GPU cluster
- **Inference**: ONNX Runtime / TensorRT, <5ms/static, <50ms/dynamic
- **Telemetry**: Real-time detection logging → drift monitoring → auto-retrain trigger

## Phased Roadmap

| Phase | Scope | Timeline |
|-------|-------|----------|
| **MVP** | Static PE classifier (LightGBM on EMBER features) + YARA rules | 8-12 weeks |
| **v1.1** | Add MalConv byte-CNN + dynamic sandbox integration | +8 weeks |
| **v1.5** | Graph NN on CFG + string transformer + ensemble | +12 weeks |
| **v2.0** | Continual learning loop, threat intel federation, kernel driver | +16 weeks |

## Critical Success Factors

1. **Clean training data** — dedup, family balance, temporal splits
2. **Adversarial robustness** — PGD/Adversarial training, feature squeezing
3. **Explainability** — SHAP on static features, attention viz on sequences
4. **Deployment constraints** — offline-capable, <100MB model, no PII exfiltration