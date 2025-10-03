# PhishGuard-AI: Advanced Email & URL Phishing Detection

**PhishGuard-AI** is a comprehensive phishing detection system that uses machine learning and external security APIs to identify phishing emails and malicious URLs in real-time.

## 🚀 Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run the Application
```bash
python app.py
```

### 3. Open Your Browser
Go to: **http://localhost:5000**

### 4. Analyze Emails
- Paste email content in the "Email Phishing Detector"
- Click "Analyze Email"
- Get instant results with 50+ features analyzed

---

## ✨ Features

### Basic Detection (Main Page)
- **URL Scanner**: Check if URLs are malicious or safe
- **Email Phishing Detector**: Analyze emails with 50+ advanced features
- **Real-time Analysis**: Instant predictions using ML model
- **Comprehensive Reports**: See exactly why an email is flagged

### Advanced Analysis (Separate Page)
- **Deep URL Analysis**: Scan with VirusTotal, URLScan.io, Google Safe Browsing, PhishTank
- **IP Reputation**: Check IPs with VirusTotal and AbuseIPDB
- **Domain Intelligence**: WHOIS lookup, domain age, reputation
- **Email Component Extraction**: Automatically analyze all URLs/IPs/domains in emails
- **Screenshots**: Visual confirmation of suspicious URLs

---

## 📊 What Gets Analyzed

### 50+ Email Features Across 7 Categories:

#### 1. Header Analysis (10 features)
- ✅ SPF authentication
- ✅ DKIM signature
- ✅ Domain mismatch (From vs Return-Path)
- ✅ Reply-To analysis
- ✅ Legitimate domain check

#### 2. Content Analysis (20 features)
- ✅ Spammy keywords (urgent, verify, suspended, etc.)
- ✅ Urgency tactics (act now, limited time)
- ✅ Threat language (account closure, legal action)
- ✅ Generic salutations ("Dear Customer")
- ✅ Financial info requests
- ✅ Text statistics (length, uppercase ratio, punctuation)

#### 3. URL Analysis (10 features)
- ✅ URL shorteners (bit.ly, tinyurl, etc.)
- ✅ IP addresses in URLs
- ✅ HTTPS vs HTTP
- ✅ Subdomain counting
- ✅ Anchor text mismatch
- ✅ Domain mismatch

#### 4. Attachment Analysis (5 features)
- ✅ Suspicious file types (.exe, .scr, .js)
- ✅ Double extensions (invoice.pdf.exe)
- ✅ Attachment count and size

#### 5. Psychological Triggers (5 features)
- ✅ Fear tactics
- ✅ Urgency pressure
- ✅ Greed triggers (free money, prizes)
- ✅ Scarcity tactics (limited offer)

#### 6. Technical Analysis (5 features)
- ✅ Homoglyph detection (look-alike characters)
- ✅ Suspicious encoding
- ✅ HTML-to-text ratio

#### 7. External API Analysis (Optional)
- ✅ VirusTotal (70+ antivirus engines)
- ✅ URLScan.io (screenshots + behavior)
- ✅ Google Safe Browsing
- ✅ AbuseIPDB (IP reputation)
- ✅ PhishTank (known phishing URLs)
- ✅ WHOIS (domain age)

---

## 🎯 How to Use

### Basic Analysis (No API Keys Needed)

1. **Start the app**: `python app.py`
2. **Open browser**: http://localhost:5000
3. **Paste email**: Copy suspicious email content
4. **Click "Analyze Email"**
5. **Review results**: See prediction + all features

### Advanced Analysis (Requires API Keys)

1. **Get free API keys** (5 minutes):
   - [VirusTotal](https://www.virustotal.com/gui/join-us) - 500 requests/day
   - [URLScan.io](https://urlscan.io/user/signup) - 100 requests/day
   - [Google Safe Browsing](https://developers.google.com/safe-browsing) - 10,000 requests/day
   - [AbuseIPDB](https://www.abuseipdb.com/register) - 1,000 requests/day

2. **Configure APIs**:
   - Go to http://localhost:5000/advanced_analysis
   - Scroll to "API Configuration"
   - Enter your API keys
   - Click "Save"

3. **Deep Analysis**:
   - Paste email in "Email Deep Analysis" tab
   - Wait 30-60 seconds
   - Get comprehensive threat intelligence from multiple sources

---

## 📁 Project Structure

```
PhishGuard-AI/
├── app.py                      # Flask application (main + advanced routes)
├── email_features.py           # Core feature extraction (50+ features)
├── advanced_analysis.py        # External API integration (7 APIs)
├── requirements.txt            # Python dependencies
├── test_email_features.py      # Developer testing tool
├── templates/
│   ├── index.html             # Main UI (basic analysis)
│   └── advanced_analysis.html # Advanced analysis UI
└── [model files]              # Pre-trained ML models
    ├── URL_detection_model.pkl
    ├── phish_detector_joblib.pkl
    └── ...
```

---

## 🔍 Example: Detecting a Phishing Email

### Input Email:
```
From: security@paypa1-verify.com
Subject: URGENT: Your Account Will Be Suspended!

Dear Customer,

Your account has been temporarily suspended due to unusual activity.
Click here immediately: http://bit.ly/verify-account

This is your final warning!
```

### PhishGuard-AI Detects:
- ❌ **Typo in domain**: "paypa1" instead of "paypal"
- ❌ **Generic salutation**: "Dear Customer"
- ❌ **Urgency keywords**: "URGENT", "immediately", "final warning"
- ❌ **URL shortener**: bit.ly
- ❌ **Threat language**: "suspended", "warning"
- ❌ **Missing SPF/DKIM**: No authentication

### Result:
**🚨 Prediction: PHISHING (95% confidence)**

### Advanced Analysis Shows:
- **VirusTotal**: 15/70 engines flag URL as malicious
- **PhishTank**: URL in known phishing database
- **WHOIS**: Domain registered 3 days ago
- **URLScan.io**: Screenshot shows fake PayPal login page

---

## 🛡️ Why Use PhishGuard-AI?

### ✅ Advantages:
1. **Comprehensive**: 50+ features + external API validation
2. **Fast**: Instant ML predictions
3. **Accurate**: Multi-source verification
4. **Visual**: See screenshots of suspicious URLs
5. **Educational**: Learn what makes emails suspicious
6. **Free**: All APIs have free tiers
7. **Privacy**: No data storage, all processing local
8. **Open Source**: Fully auditable code

### ❌ What It Cannot Do:
- Scan attachment contents for malware (use antivirus)
- Guarantee 100% accuracy (no system is perfect)
- Check if a company actually sent an email (contact them directly)
- Protect you from all threats (use multiple security layers)

---

## 🔧 For Developers

### Test Feature Extraction:
```bash
python test_email_features.py
```

This runs 4 test cases showing how different phishing tactics are detected.

### Add New Features:
Edit `email_features.py` and add to any feature extractor class:
```python
@staticmethod
def your_new_feature(text):
    # Your logic here
    return feature_value
```

### Add New APIs:
Edit `advanced_analysis.py` and create a new analyzer class:
```python
class NewAPIAnalyzer:
    @staticmethod
    def analyze(data):
        # API call logic
        return results
```

---

## 📚 Technical Details

### Machine Learning Model:
- **Algorithm**: Logistic Regression / Random Forest (from your training)
- **Features**: 50+ engineered features
- **Vectorization**: TF-IDF for text + scaled numeric features
- **Training**: Based on SpamAssassin + Nazario phishing datasets

### External APIs:
- **VirusTotal**: Multi-engine scanning (70+ vendors)
- **URLScan.io**: Automated browser analysis
- **Google Safe Browsing**: Google's threat database
- **AbuseIPDB**: Community-driven IP reputation
- **PhishTank**: Verified phishing URL database
- **WHOIS**: Domain registration information

### Architecture:
```
User Input → Feature Extraction → ML Model → Prediction
                    ↓
            (Optional) External APIs → Deep Analysis
```

---

## 🚨 Important Notes

### Security & Privacy:
- ✅ Emails analyzed in real-time, not stored
- ✅ API keys stored in memory only
- ✅ No data sent to third parties (except for deep analysis when requested)
- ✅ All processing on your server

### Best Practices:
1. **Use PhishGuard-AI as ONE tool** among many security measures
2. **Always verify suspicious emails** through official channels
3. **Don't click links** in emails flagged as phishing
4. **Report phishing** to your email provider
5. **Stay informed** about new phishing tactics

### Rate Limits:
- VirusTotal: 4 requests/minute, 500/day
- URLScan.io: 100 requests/day
- Google Safe Browsing: 10,000 requests/day
- AbuseIPDB: 1,000 requests/day
- PhishTank: Unlimited (no key required)

---

## 🐛 Troubleshooting

### "ModuleNotFoundError"
```bash
pip install -r requirements.txt
```

### "Model file not found"
Make sure `URL_detection_model.pkl` and `phish_detector_joblib.pkl` are in the project root.

### "API key not configured"
Go to http://localhost:5000/advanced_analysis and configure your API keys.

### "Rate limit exceeded"
Wait a few minutes. Free tier APIs have rate limits.

---

## 📄 License

This project is open source. Feel free to use, modify, and distribute.

---

## 🤝 Contributing

Contributions welcome! Areas for improvement:
- Additional feature extraction methods
- New external API integrations
- UI/UX enhancements
- Model retraining with new datasets
- Performance optimizations

---

## 📞 Support

For issues or questions:
- Check the `test_email_features.py` for examples
- Review the code comments in `email_features.py` and `advanced_analysis.py`
- Open an issue on GitHub

---

## 🎓 Learn More

This project demonstrates:
- Feature engineering for security applications
- ML-based classification
- External API integration
- Full-stack web development (Flask + HTML/JS)
- Security best practices

---

**Remember: PhishGuard-AI helps you make informed decisions, but always trust your instincts and verify suspicious communications through official channels!** 🛡️

---

## 📝 Changelog

### Version 2.0 (Current)
- ✅ Added 50+ comprehensive email features
- ✅ Integrated 7 external security APIs
- ✅ Advanced analysis page with deep investigation
- ✅ URL screenshot capability
- ✅ Domain age and WHOIS lookup
- ✅ IP reputation checking
- ✅ Multi-source verdict aggregation

### Version 1.0
- Basic URL detection
- Simple email analysis
- ML model training uses machine learning algorithms to detect **phishing URLs** by analyzing the structural and semantic properties of URLs. The project trains a model on features extracted from a dataset of **phishing URLs** and **legitimate URLs**. The resulting model can classify new URLs as either phishing or legitimate.
```
---

## Future Enhancements (Planned)

While the current version of PhisGaurd-AI focuses on phishing **URL detection**, the following features are planned for future updates:
```
- **Full Email Detection**: Expansion of the system to analyze phishing **email content** along with **URLs**.
- **Phishing Attachment Detection**: Adding the ability to analyze email attachments and flag potential phishing content.
- **Real-Time Detection and Alerts**: Implementing a live phishing detection system that can provide **real-time notifications** when phishing URLs are detected.
- **Explainable AI (XAI)**: Adding interpretable explanations for why a particular URL is classified as phishing, using tools like **LIME** or **SHAP**.
- **Web Dashboard**: Building a dashboard to visualize phishing detection trends, statistics, and more in real time.
- **Email Integration**: Allowing integration with popular email services (e.g., Gmail, Outlook) to scan incoming emails for phishing attempts.
```
---

## Installation

To install and run PhisGaurd-AI locally, follow these steps:

### 1. Clone the repository:

```bash
git clone https://github.com/Pranavrh53/PhisGaurd-AI.git
cd PhisGaurd-AI
