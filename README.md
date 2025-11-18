# 🛡️ PhishGuard-AI

**AI-Powered Email & URL Phishing Detection System**

<div align="center">
  <img src="https://img.icons8.com/color/96/000000/cyber-security.png" width="110" />
  <br>
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue" />
  <img src="https://img.shields.io/badge/License-MIT-green" />
</div>

---

## 🌟 Overview

PhishGuard-AI is a real-time phishing detection system for:

- **URLs**
- **Emails**
- **IP addresses**
- **Domains**
- **Attachments**

It leverages machine learning (ML), 50+ engineered features, deep threat intelligence, and Explainable AI (XAI) to provide high accuracy and actionable insights.


## ✨ Key Features

### Real-Time Phishing Detection

- URL classification via ML models
- Email phishing prediction (50+ features)
- Instant confidence scoring

### Deep Threat Intelligence (Advanced Analysis)

| Capability                  | API Used            | Description                 |
|-----------------------------|---------------------|-----------------------------|
| Multi-engine URL scan       | VirusTotal          | 70+ antivirus engines       |
| Browser scan, screenshot    | URLScan.io          | Behavioral analysis         |
| Known phishing lookup       | PhishTank           | Community-verified sites    |
| Threat Database             | Google SafeBrowsing | Malware / phishing lists    |
| IP Reputation               | AbuseIPDB           | Abuse reports               |
| Domain Intelligence         | WHOIS               | Domain age, registrar info  |

### Automatic Email Component Extraction

Automatically extracts:
- URLs
- IP addresses
- Sender domain
- Return-Path, Reply-To
- Attachments
- HTML structure

### Explainable AI (XAI)

Provides explanations for flagged emails:
- Suspicious words
- Spoofed domains
- Authentication failures (SPF/DKIM/DMARC)
- Mismatched headers
- URL redirection patterns

---

## 🚀 Quick Start

```sh
# 1. Clone the Repository
git clone https://github.com/Pranavrh53/PhisGaurd-AI.git
cd PhisGaurd-AI

# 2. Set Up Virtual Environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3. Install Dependencies
pip install -r requirements.txt

# 4. Run the Application
python app.py

# Open in browser:
# http://localhost:5000
```

---

## 🧪 Usage

### Basic Analysis (No API Keys Needed)

1. Open main page
2. Paste email or URL to analyze
3. Click "Analyze"
4. View prediction & explanation

### Advanced Analysis (Requires API Keys for APIs)

Supported APIs: VirusTotal, URLScan, SafeBrowsing, AbuseIPDB, PhishTank, WHOIS

To enable:
1. Go to `/advanced_analysis`
2. Enter your API keys
3. Click "Save"

---

## 📊 Feature Breakdown

**1. Header Features**
- SPF, DKIM, DMARC
- Sender mismatch, Reply-To anomalies

**2. Content Features**
- Urgent/threat language
- Spam keywords
- HTML/text ratio
- Uppercase/special characters

**3. URL Features**
- Shorteners, IP-based URLs
- Subdomain depth, protocol checks
- Mismatch between URL text & href

**4. Attachments**
- Suspicious/double extensions
- Heuristic file analysis

**5. Psychological Features**
- Fear, urgency, scarcity, greed usage

**6. Technical Features**
- Homoglyph detection
- Encoding irregularities

---

## 📁 Project Structure

```
PhishGuard-AI/
│
├── app.py                     # Flask backend entry
├── requirements.txt           # Python dependencies
│
├── email_features.py          # 50+ email features
├── advanced_analysis.py       # Threat-intelligence API integration
├── test_email_features.py     # Unit tests
│
├── models/                    # ML models
│   ├── URL_detection_model.pkl
│   └── phish_detector_joblib.pkl
│
├── templates/                 # HTML pages
│   ├── index.html
│   └── advanced_analysis.html
│
├── static/
│   ├── css/
│   └── js/
│
├── extension/                 # Browser extension (WIP)
│
└── notebooks/                 # Model training notebooks
    ├── URL_detection_model.ipynb
    └── Email_Phishing_Model.ipynb
```

---

## 🧠 Technical Details

- **Machine Learning:** Logistic Regression & Random Forest
- **Feature Engineering:** TF-IDF, manual feature sets
- **Datasets:** Nazario, SpamAssassin, curated datasets

**Architecture:**

`User Input → Feature Extraction → ML Model → Prediction`
```
                ↓
       (Optional) Deep Threat Intelligence APIs
```

---

## 🚀 Planned Enhancements

- Attachment malware scanning
- Gmail/Outlook integration
- Browser real-time protection
- Live dashboard analytics
- SHAP-based advanced XAI visualizations

---

## 🤝 Contributing

1. Create a feature branch:
   ```sh
   git checkout -b feature/my-feature
   ```
2. Commit your changes:
   ```sh
   git commit -m "Add my feature"
   ```
3. Push & open a Pull Request:
   ```sh
   git push origin feature/my-feature
   ```
   > All contributions and suggestions are welcome!

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
