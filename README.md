# AI Antivirus

ML-powered malware detection system with static, dynamic, and ensemble detection layers.

## Project Structure

```
ai-antivirus/
├── PLAN.md                 # Architecture & roadmap
├── README.md               # This file
├── requirements.txt        # Python dependencies
├── configs/
│   └── model.yaml          # Model hyperparameters
├── src/
│   ├── static/             # Static analysis (PE/ELF)
│   │   ├── __init__.py
│   │   └── ember_features.py    # EMBER feature extractor
│   ├── dynamic/            # Dynamic analysis (sandbox)
│   │   └── __init__.py
│   ├── ensemble/           # Model stacking & calibration
│   │   └── __init__.py
│   ├── rules/              # YARA + ML rule generation
│   │   └── __init__.py
│   └── api/                # FastAPI inference server
│       └── __init__.py
├── scripts/
│   └── train_ember_lgbm.py # LightGBM baseline training
├── notebooks/              # EDA & experiment tracking
├── tests/                  # Unit tests
├── models/                 # Trained model artifacts (gitignored)
└── data/                   # Datasets (gitignored)
```

## Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Download EMBER 2018 Dataset
```bash
# From https://github.com/elastic/ember
# Place in data/ember2018/
```

### 3. Train Baseline (MVP)
```bash
python scripts/train_ember_lgbm.py --data-dir data/ember2018 --output models/ember_lgbm.txt
```

### 4. Run Inference
```python
from src.static.ember_features import extract_ember_features
import lightgbm as lgb

model = lgb.Booster(model_file='models/ember_lgbm.txt')
features = extract_ember_features('suspicious.exe')
score = model.predict([features], num_iteration=model.best_iteration)[0]
print(f"Malicious probability: {score:.4f}")
```

## Development Phases

| Phase | Target | Status |
|-------|--------|--------|
| **MVP** | LightGBM on EMBER features + YARA | 🔄 In Progress |
| **v1.1** | MalConv byte-CNN + sandbox integration | ⏳ Planned |
| **v1.5** | CFG Graph NN + string transformer + ensemble | ⏳ Planned |
| **v2.0** | Continual learning + kernel driver | ⏳ Planned |

## Key References

- **EMBER**: Anderson et al., "EMBER: An Open Dataset for Training Static PE Malware Classifiers" (2018)
- **MalConv**: Raff et al., "Malware Detection by Eating a Whole EXE" (2018)
- **Sorel-20M**: Harang & Rudd, "Sorel-20M: A Large Scale Benchmark Dataset" (2020)

## License

Proprietary - Internal Research Project