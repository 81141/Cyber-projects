# ML_URL_Fraud — Malicious URL Detection

A machine learning pipeline that detects malicious URLs (phishing, malware, defacement) using lexical analysis and passive OSINT enrichment.

---

## Project Structure

```
03_ML_URL_Fraud/
├── data/
│   ├── Full_lexical_features.csv
│   ├── lexical_features.csv
│   ├── Passive_features.csv
│   └── malicious_phish.csv
├── src/
│   ├── Ipynb/
│   │   ├── Lexical.ipynb
│   │   ├── Model_2k_passive.ipynb
│   │   └── Model_600k_lexical.ipynb
│   ├── passive_osint.py            
│   ├── data_scraper.py             
│   └── test.py           
├── Model/
│   ├── RandomForest_model.pkl                
│   ├── xgb_model.pkl               
│   └── label_encoder.pkl           
├── keys/
└── Latex notes/
```

---

## How It Works

```
Raw URLs
   ↓
Lexical Feature Extraction  (URL structure, length, special chars, entropy)
   ↓
Passive OSINT Enrichment    (WHOIS age, IP metadata, DGA detection)
   ↓
ML Classification           (benign / phishing / malware / defacement)
```

---

## Features

**Lexical features** - extracted from the URL string itself:
- URL length, domain length, path length
- Number of dots, hyphens, digits, special characters
- Presence of IP address, `@` symbol, double slash redirect
- Domain entropy, number of subdomains

**Passive OSINT features** - from external sources:
- `domain_age_days` - how old the domain is (WHOIS)
- `asn_org`, `country`, `region` - hosting infrastructure (IPInfo)
- `is_dga_like` - entropy-based DGA detection
- `suspicious_domain` - young domain + high entropy composite signal

---

## Results

| Model | Dataset | Macro F1 |
|---|---|---|
| Random Forest | 600k lexical only | **0.9287** |
| XGBoost | 600k lexical only | 0.9251 |
| XGBoost | 2k + passive OSINT | 0.9140 |

The Randome Forest trained on 600k shows the best results.

---

## Setup

```bash
pip install pandas numpy scikit-learn xgboost whoisit ipinfo joblib
```

You will need:
- An [IPInfo](https://ipinfo.io) API key saved to `keys/API_TOKEN.txt`

---

## Usage

1. Run `Lexical.ipynb` to extract lexical features from raw URLs
2. Run `data_scraper.py` to enrich a sample with passive OSINT
3. Run `ML_model.ipynb` to train and evaluate models

To load and use the saved model:

```python
import joblib
import pandas as pd

rf = joblib.load('model/rf_model.pkl')
le = joblib.load('model/label_encoder.pkl')

# Pass a row of lexical features
prediction = rf.predict([feature_row])
print('Predicted class:', le.inverse_transform(prediction))
```

---

## Limitations

- Passive OSINT enrichment was run on a 2k sample due to API rate limits
- WHOIS lookups fail on dead/taken-down malicious domains
- VirusTotal enrichment was excluded due to free tier rate limits (4 req/min)
- The enriched model scores slightly lower than the base model due to limited sample size, not because OSINT features are unhelpful
