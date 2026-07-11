# 🔐 PhishGuard — Phishing URL Detector

> ML-powered phishing URL detection tool achieving 97.06% accuracy, built with Python & Streamlit.

![Python](https://img.shields.io/badge/Python-3.14-blue?style=flat-square&logo=python)
![XGBoost](https://img.shields.io/badge/XGBoost-3.3.0-orange?style=flat-square)
![Streamlit](https://img.shields.io/badge/Streamlit-1.58-red?style=flat-square&logo=streamlit)
![Accuracy](https://img.shields.io/badge/Accuracy-97.06%25-brightgreen?style=flat-square)

**[🌐 Live Demo](https://phishing-detector-3tnddj6kypaxg9vq4p9pyy.streamlit.app)**

---

## What is PhishGuard?

PhishGuard is a real-time phishing URL detection tool that analyzes any URL and instantly tells you whether it is **safe**, **suspicious**, or a **phishing attempt** — with a confidence score and a breakdown of flagged indicators.

---

## Features

- **Real-time URL scanning** with animated terminal-style interface
- **97.06% accuracy** on 11,054 URLs using XGBoost classifier
- **Confidence score** for every prediction
- **Flagged indicators** breakdown — shows exactly why a URL was flagged
- **3 risk levels** — Safe / Suspicious / Dangerous
- **Session history** — last 5 scanned URLs visible at a glance
- **Shareable scan report** — copy and share results instantly
- **Rule-based override system** — catches obvious phishing patterns the model might miss
- **Safe domain whitelist** — prevents false positives on known legitimate sites

---

## Tech Stack

| Tool | Purpose |
|------|---------|
| Python | Core language |
| XGBoost | ML classifier (97.06% accuracy) |
| scikit-learn | Model training, evaluation, train/test split |
| Streamlit | Web interface |
| pandas | Dataset loading and manipulation |
| joblib | Model serialization |

---

## How It Works

1. User pastes a URL into the interface
2. `features.py` extracts 30 security features from the raw URL
3. A rule-based layer checks for obvious phishing signals (IP in domain, URL shorteners, suspicious keywords)
4. The trained XGBoost model predicts phishing vs legitimate
5. Results are displayed with confidence score and flagged indicators

### Features Extracted
- IP address in domain
- URL length
- Presence of URL shorteners
- `@` symbol, `//` redirects, `-` in domain
- Subdomain count
- HTTPS usage
- Suspicious keywords in path
- And 22 more...

---

## Dataset

- **Source:** [Phishing Website Detector — Kaggle](https://www.kaggle.com/datasets/eswarchandt/phishing-website-detector)
- **Size:** 11,054 URLs with 30 pre-extracted features
- **Labels:** -1 (phishing) → 0, +1 (legitimate) → 1

---

## Model Performance

| Metric | Phishing | Legitimate | Overall |
|--------|----------|------------|---------|
| Precision | 98% | 97% | 97% |
| Recall | 95% | 98% | 97% |
| F1-Score | 97% | 97% | 97% |
| Support | 976 URLs | 1,235 URLs | 2,211 URLs |

---

## Run Locally

```bash
# Clone the repo
git clone https://github.com/justttleyla-bot/phishing-detector.git
cd phishing-detector

# Install dependencies
pip install -r requirements.txt

# Train the model (first time only)
python train.py

# Run the app
streamlit run app.py
```

---

## Project Structure
phishing-detector/
├── app.py              # Streamlit web interface
├── features.py         # URL feature extraction + rule-based override
├── train.py            # Model training pipeline
├── safelist.py         # Known legitimate domains whitelist
├── model.pkl           # Trained XGBoost model
├── phishing.csv        # Dataset
└── requirements.txt    # Dependencies

---

## Author

**Leyla** — Data Science & Computer Science Student

[![GitHub](https://img.shields.io/badge/GitHub-justttleyla--bot-black?style=flat-square&logo=github)](https://github.com/justttleyla-bot)
[![Live Demo](https://img.shields.io/badge/Live-Demo-brightgreen?style=flat-square)](https://phishing-detector-3tnddj6kypaxg9vq4p9pyy.streamlit.app)