🛡️ PhishGuard-AI
AI-Powered Email & URL Phishing Detection System
<div align="center"> <img src="https://img.icons8.com/color/96/000000/cyber-security.png" width="110" /> <p> <img src="https://img.shields.io/badge/Python-3.8+-blue" /> <img src="https://img.shields.io/badge/Flask-3.0+-green" /> <img src="https://img.shields.io/badge/Machine%20Learning-Active-blueviolet" /> <img src="https://img.shields.io/badge/License-MIT-brightgreen" /> </p> <p> <a href="#-overview">Overview</a> • <a href="#-key-features">Features</a> • <a href="#-quick-start">Quick Start</a> • <a href="#-usage">Usage</a> • <a href="#-project-structure">Project Structure</a> • <a href="#-technical-details">Technical Details</a> • <a href="#-future-enhancements">Future Enhancements</a> • <a href="#-contributing">Contributing</a> </p> </div>
🌟 Overview

PhishGuard-AI is a real-time phishing detection system that analyzes:

✔️ URLs
✔️ Emails
✔️ IPs
✔️ Domains
✔️ Attachments

It combines machine learning, 50+ engineered email features, deep threat intelligence APIs, and Explainable AI to detect phishing attempts with high accuracy.

✨ Key Features
🔹 Real-Time Phishing Detection

URL classification using ML models

Email phishing prediction (50+ features)

Instant confidence score

🔹 Deep Threat Intelligence (Advanced Analysis)
Capability	API Used	Description
Multi-engine URL scan	VirusTotal	70+ antivirus engines
Browser scan + screenshot	URLScan.io	Behavioral analysis
Known phishing lookup	PhishTank	Community verified
Threat database	Google Safe Browsing	Malware / phishing list
IP reputation	AbuseIPDB	Abuse reports
Domain Intelligence	WHOIS	Domain age, registrar
🔹 Automatic Email Component Extraction

URLs

IP addresses

Sender domain

Return-Path

Reply-To

Attachments

HTML structure

🔹 Explainable AI (XAI)

Shows why an email was flagged:

Suspicious words

Spoofed domains

Authentication failures

Mismatching sender headers

URL redirection patterns

🚀 Quick Start
1. Clone the Repo
git clone https://github.com/yourusername/PhishGuard-AI.git
cd PhishGuard-AI

2. Create Virtual Environment
python -m venv venv
source venv/bin/activate       # Windows: venv\Scripts\activate

3. Install Dependencies
pip install -r requirements.txt

4. Run the App
python app.py


Visit:
👉 http://localhost:5000

🧪 Usage
✔ Basic Analysis (No API Keys)

Open main page

Paste email or URL

Click Analyze

Get prediction + explanation

✔ Advanced Analysis (Requires API Keys)

Supports:

VirusTotal

URLScan

Safe Browsing

AbuseIPDB

PhishTank

WHOIS

To enable:

Go to /advanced_analysis

Enter API keys

Save

📊 What Gets Analyzed (50+ Features)
1. Header Features

SPF

DKIM

DMARC

Sender mismatch

Reply-To anomalies

2. Content Features

Urgent language

Threat words

Spam keywords

HTML to text ratio

Uppercase / special character counts

3. URL Features

Shorteners

IP-based URLs

Subdomain depth

Protocol check

Mismatch between text and href

4. Attachments

Suspicious extensions

Double extensions

File naming heuristics

5. Psychological Features

Fear

Urgency

Scarcity

Greed

6. Technical Features

Homoglyph detection

Encoding irregularities

📁 Project Structure
PhishGuard-AI/
│
├── app.py                     # Flask backend
├── requirements.txt
│
├── email_features.py          # 50+ email features
├── advanced_analysis.py        # API integrations
├── test_email_features.py
│
├── models/
│   ├── URL_detection_model.pkl
│   └── phish_detector_joblib.pkl
│
├── templates/
│   ├── index.html
│   └── advanced_analysis.html
│
├── static/
│   ├── css/
│   └── js/
│
├── extension/                 # Browser extension
│
└── notebooks/                 # Model training
    ├── URL_detection_model.ipynb
    └── Email_Phishing_Model.ipynb

🧠 Technical Details
Machine Learning

Logistic Regression / Random Forest

TF-IDF + engineered features

Dataset: Nazario + SpamAssassin + curated datasets

Architecture
User Input → Feature Extraction → ML Model → Prediction
                       ↓
          (Optional) Deep Threat Intelligence APIs

🚀 Future Enhancements

Attachment malware scanning

Gmail/Outlook integration

Browser real-time protection

Live dashboard analytics

SHAP-based XAI visualizations

🤝 Contributing
git checkout -b feature/new-feature
git commit -m "Added new feature"
git push origin feature/new-feature


Open a PR!

📄 License

MIT License
