🛡️ PhishGuard-AI
AI-Powered Email & URL Phishing Detection System
<div align="center"> <img src="https://img.icons8.com/color/96/000000/cyber-security.png" width="110" /> <h3>Protect Your Digital Life with Intelligent Phishing Detection</h3> <p> <img src="https://img.shields.io/badge/Python-3.8+-blue" /> <img src="https://img.shields.io/badge/Flask-3.0+-green" /> <img src="https://img.shields.io/badge/Machine%20Learning-Active-blueviolet" /> <img src="https://img.shields.io/badge/License-MIT-brightgreen" /> </p> <p> <a href="#-features">Features</a> • <a href="#-quick-start">Quick Start</a> • <a href="#-project-structure">Project Structure</a> • <a href="#-technical-details">Technical Details</a> • <a href="#-future-enhancements">Future Enhancements</a> • <a href="#-contributing">Contributing</a> </p> </div>
🌟 Overview

PhishGuard-AI is a complete phishing detection suite that combines:

✔️ Machine Learning
✔️ Email Feature Engineering (50+ features)
✔️ URL Intelligence APIs
✔️ Explainable AI
✔️ Real-time threat scoring

It detects phishing URLs, analyzes email content, checks domain/IP reputation, validates sender authentication, and provides multi-source threat intelligence.

✨ Key Features
🔹 1. Real-Time Phishing Detection

URL classification using ML models

Email phishing prediction using 50+ engineered features

Instant confidence scoring

🔹 2. Deep Threat Intelligence (Advanced Analysis Page)
Capability	Integrated API
Multi-engine URL scanning	VirusTotal
Smart browser-based scanning + Screenshots	URLScan.io
Known phishing DB check	PhishTank
Google threat database lookup	Safe Browsing API
IP reputation check	AbuseIPDB
Domain age & WHOIS analysis	WHOIS
🔹 3. Email Component Auto-Extraction

Extracts & analyzes:

URLs

IP addresses

Sender domain

Return-Path

Reply-To

Attachments

HTML structure

🔹 4. Explainable AI (XAI)

See exactly why an email was flagged:

Keyword triggers

Domain mismatch

Authentication failures

Suspicious URLs

Sender anomalies

🔹 5. Browser Extension (Optional Folder)

Instant URL check inside the browser

One-click phishing insights

🚀 Quick Start
Prerequisites

Python 3.8+

pip

Modern Browser for extension (optional)

Installation
# Clone the repo
git clone https://github.com/yourusername/PhishGuard-AI.git
cd PhishGuard-AI

# Create virtual environment
python -m venv venv
source venv/bin/activate       # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

Run the Application
python app.py


Now open:

👉 http://localhost:5000

🧪 Using PhishGuard-AI
✔️ Basic Email & URL Analysis (No API Keys Needed)

Open main page

Paste suspicious email or URL

Click Analyze

Get ML prediction + feature breakdown

✔️ Deep Advanced Analysis (API Keys Required)

Supports:

API	Purpose
VirusTotal	Scan URLs/IPs/domain with 70+ antivirus engines
URLScan.io	Browser scan, screenshot, behavior
Safe Browsing	Google’s threat database
AbuseIPDB	IP reputation
PhishTank	Known phishing URLs
WHOIS	Domain age, registrar
Setup API Keys:

Visit
👉 http://localhost:5000/advanced_analysis

Scroll to API Configuration

Enter your API keys

Save

📊 What Gets Analyzed (50+ Features)
1. Header Analysis

SPF, DKIM, DMARC validation

Domain mismatch (From vs Reply-To)

Return-Path anomalies

2. Content Analysis

Spam keywords

Urgency indicators

Threat language

HTML-to-text ratio

Uppercase & punctuation score

3. URL Analysis

IP-based URLs

Subdomain depth

HTTPS/HTTP check

URL shorteners

Domain mismatch

4. Attachments

Suspicious filetypes

Double extensions

Size heuristics

5. Psychological Indicators

Fear

Urgency

Scarcity

Greed

6. Technical Anomalies

Homoglyph detection

Suspicious encoding

Strange character sets

📁 Project Structure
PhishGuard-AI/
│
├── app.py                       # Flask backend (basic + advanced routes)
├── requirements.txt             # Dependencies
│
├── email_features.py            # 50+ feature extraction functions
├── advanced_analysis.py         # All API integrations (VT, URLScan, AbuseIPDB...)
├── test_email_features.py       # Developer test cases
│
├── models/ or root/
│   ├── URL_detection_model.pkl
│   └── phish_detector_joblib.pkl
│
├── templates/
│   ├── index.html               # Basic analysis UI
│   └── advanced_analysis.html   # Deep analysis dashboard
│
├── static/
│   ├── css/
│   └── js/
│
├── extension/                   # Browser extension (optional)
│   ├── background.js
│   ├── content.js
│   ├── popup.html
│   └── icons/
│
├── notebooks/                   # Model training notebooks
│   ├── URL_detection_model.ipynb
│   └── Email_Phishing_Model.ipynb
│
└── utils/
    ├── xai_handler.py           # LIME/SHAP explainable AI
    └── advanced_analysis.py     # API handlers

🧠 Technical Details
✔️ Machine Learning

Models: Logistic Regression / Random Forest

Feature set: 50+ features

Dataset: Nazario phishing + SpamAssassin + custom cleaned datasets

Preprocessing: TF-IDF, normalization, categorical encodings

✔️ Architecture
User Input
     ↓
Feature Extraction (email_features.py)
     ↓
ML Model (URL or Email)
     ↓
Prediction + Confidence
     ↓
(OPTIONAL) Deep Analysis → External Security APIs

🛡️ Security & Privacy

No email content stored

API keys stored only in session memory

No external API calls unless user enables deep analysis

Local processing on your machine

🚨 Example Detection

Email:

From: security@paypa1-support.com
Subject: URGENT: Your Account is Suspended!

Click here: http://bit.ly/verify-now


Flags detected:

❌ Domain spoofing (“paypa1”)

❌ URL shortener

❌ Urgency keywords

❌ No DKIM/SPF

❌ Threat language

Result:

🚨 PHISHING — 95% Confidence
🚀 Future Enhancements

Full attachment malware scanning

Gmail/Outlook integration

Real-time browser monitoring

SHAP-based visual explanations

Cloud dashboard with analytics

Auto-blocking via browser extension

🤝 Contributing
git checkout -b feature/NewFeature
git commit -m "Added NewFeature"
git push origin feature/NewFeature


Open a Pull Request!

📄 License

MIT License — Free for personal & commercial use.

❤️ Acknowledgments

Icons by Icons8

Open-source security datasets

VirusTotal, URLScan.io, Google Safe Browsing APIs

Built with ❤️ by the PhishGuard-AI Team
