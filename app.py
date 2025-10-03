from flask import Flask, request, render_template, jsonify, redirect, url_for
import joblib
import pandas as pd
import numpy as np
from scipy.sparse import hstack
from email_features import extract_all_features
from advanced_analysis import (
    URLAnalyzer, IPAnalyzer, DomainAnalyzer, FileAnalyzer,
    analyze_email_components, get_api_status, set_api_key
)
import re
from urllib.parse import urlparse

# ------------------ Load Models ------------------
# URL model + preprocessing assets
url_model = joblib.load("pkl/URL_detection_model.pkl")
expected_columns = joblib.load("pkl/expected_columns.pkl")
top_tlds = joblib.load("pkl/top_tlds.pkl")

# Email model + preprocessing assets
email_assets = joblib.load("pkl/phish_detector_joblib.pkl")
vectorizer = email_assets["vectorizer"]
scaler = email_assets["scaler"]
numeric_cols = email_assets["numeric_cols"]
email_model = email_assets["model"]

# ------------------ Flask Init ------------------
app = Flask(__name__)

# ------------------ Feature Extraction: URL ------------------
def extract_features(url):
    """Match preprocessing logic from training notebook."""
    features = {
        "url_length": len(url),
        "num_dots": url.count(".")
    }

    # Example: top TLDs
    for tld in top_tlds:
        features[f"tld_{tld}"] = 1 if url.endswith(tld) else 0

    # Convert dict → DataFrame
    df = pd.DataFrame([features])
    df = df.reindex(columns=expected_columns, fill_value=0)
    return df

# ------------------ Feature Extraction: Email ------------------
def preprocess_raw_email(raw_email_str):
    """
    Extract comprehensive features from raw email string
    Uses the advanced email_features module for feature extraction
    """
    # Extract all features using the comprehensive feature extractor
    features = extract_all_features(raw_email_str)
    
    # Ensure all expected features exist with default values
    default_features = {
        "body": raw_email_str,
        "subj_len": 0,
        "subj_words": 0,
        "body_len": len(raw_email_str),
        "body_words": len(raw_email_str.split()),
        "uppercase_ratio": 0,
        "exclaim_count": 0,
        "question_count": 0,
        "num_urls": 0,
        "num_ip_urls": 0,
        "num_shorteners": 0,
        "avg_url_len": 0,
        "num_unique_domains": 0,
        "num_attachments": 0,
        "domain_mismatch": 0,
        "from_return_mismatch": 0,
        "has_spf": 0,
        "has_dkim": 0,
        "has_suspicious_attachment": 0,
        "kw_verify": 0,
        "kw_password": 0,
        "kw_account": 0,
        "kw_urgent": 0,
        "kw_click here": 0,
        "kw_bank": 0,
        "kw_login": 0,
        "kw_update": 0,
        "kw_suspend": 0,
        "kw_confirm": 0,
        "kw_security": 0,
        "kw_ssn": 0,
        "kw_credit card": 0,
    }
    
    # Merge extracted features with defaults
    default_features.update(features)
    
    return pd.DataFrame([default_features])


# ------------------ Routes ------------------

@app.route("/", methods=["GET"])
def home():
    return render_template("index.html")


@app.route("/check_url", methods=["POST"])
def check_url():
    url = request.form["url"]

    # Extract features
    X = extract_features(url)

    # Predict probabilities
    probabilities = url_model.predict_proba(X)[0]
    benign_prob = probabilities[0]
    malicious_prob = probabilities[1]

    # Get prediction
    prediction = "Benign" if benign_prob > malicious_prob else "Malicious"

    return render_template(
        "index.html",
        prediction_result={
            "url": url,
            "prediction": prediction,
            "prob_benign": f"{benign_prob:.2f}",
            "prob_malicious": f"{malicious_prob:.2f}",
        }
    )


@app.route("/check_email", methods=["POST"])
def check_email():
    raw_email = request.form.get("email", "")

    # Extract features
    df = preprocess_raw_email(raw_email)

    # Text features
    X_text = vectorizer.transform(df["body"])

    # Numeric features
    X_num = df[numeric_cols].values
    X_num = scaler.transform(X_num)

    # Combine
    X_final = hstack([X_text, X_num])

    # Predict
    pred = email_model.predict(X_final)[0]
    prob = email_model.predict_proba(X_final)[0][1]

    # Extract comprehensive features for response
    features_dict = {
        # Basic statistics
        "body_length": int(df["body_len"].values[0]) if "body_len" in df.columns else 0,
        "body_words": int(df["body_words"].values[0]) if "body_words" in df.columns else 0,
        "uppercase_ratio": float(df["uppercase_ratio"].values[0]) if "uppercase_ratio" in df.columns else 0,
        "exclamation_marks": int(df["exclaim_count"].values[0]) if "exclaim_count" in df.columns else 0,
        "question_marks": int(df["question_count"].values[0]) if "question_count" in df.columns else 0,
        
        # URL features
        "num_urls": int(df["num_urls"].values[0]) if "num_urls" in df.columns else 0,
        "num_shorteners": int(df["num_shorteners"].values[0]) if "num_shorteners" in df.columns else 0,
        "num_ip_urls": int(df["num_ip_urls"].values[0]) if "num_ip_urls" in df.columns else 0,
        "domain_mismatch": bool(df["domain_mismatch"].values[0]) if "domain_mismatch" in df.columns else False,
        
        # Attachment features
        "num_attachments": int(df["num_attachments"].values[0]) if "num_attachments" in df.columns else 0,
        "has_suspicious_attachment": bool(df["has_suspicious_attachment"].values[0]) if "has_suspicious_attachment" in df.columns else False,
        
        # Header features
        "has_spf": bool(df["has_spf"].values[0]) if "has_spf" in df.columns else False,
        "has_dkim": bool(df["has_dkim"].values[0]) if "has_dkim" in df.columns else False,
        "from_return_mismatch": bool(df["from_return_mismatch"].values[0]) if "from_return_mismatch" in df.columns else False,
        
        # Content features
        "spammy_keyword_count": int(df["spammy_keyword_count"].values[0]) if "spammy_keyword_count" in df.columns else 0,
        "urgency_keyword_count": int(df["urgency_keyword_count"].values[0]) if "urgency_keyword_count" in df.columns else 0,
        "threat_keyword_count": int(df["threat_keyword_count"].values[0]) if "threat_keyword_count" in df.columns else 0,
        "has_generic_salutation": bool(df["has_generic_salutation"].values[0]) if "has_generic_salutation" in df.columns else False,
        
        # Psychological features
        "emotion_fear": int(df["emotion_fear"].values[0]) if "emotion_fear" in df.columns else 0,
        "emotion_urgency": int(df["emotion_urgency"].values[0]) if "emotion_urgency" in df.columns else 0,
        "emotion_greed": int(df["emotion_greed"].values[0]) if "emotion_greed" in df.columns else 0,
        "scarcity_score": int(df["scarcity_score"].values[0]) if "scarcity_score" in df.columns else 0,
        
        # Technical features
        "homoglyph_count": int(df["homoglyph_count"].values[0]) if "homoglyph_count" in df.columns else 0,
        "suspicious_encoding": bool(df["suspicious_encoding"].values[0]) if "suspicious_encoding" in df.columns else False,
        
        # Individual keyword flags
        "suspicious_keywords": {
            "verify": bool(df["kw_verify"].values[0]) if "kw_verify" in df.columns else False,
            "password": bool(df["kw_password"].values[0]) if "kw_password" in df.columns else False,
            "account": bool(df["kw_account"].values[0]) if "kw_account" in df.columns else False,
            "urgent": bool(df["kw_urgent"].values[0]) if "kw_urgent" in df.columns else False,
            "click_here": bool(df["kw_click here"].values[0]) if "kw_click here" in df.columns else False,
            "bank": bool(df["kw_bank"].values[0]) if "kw_bank" in df.columns else False,
            "login": bool(df["kw_login"].values[0]) if "kw_login" in df.columns else False,
            "update": bool(df["kw_update"].values[0]) if "kw_update" in df.columns else False,
            "suspend": bool(df["kw_suspend"].values[0]) if "kw_suspend" in df.columns else False,
            "confirm": bool(df["kw_confirm"].values[0]) if "kw_confirm" in df.columns else False,
            "security": bool(df["kw_security"].values[0]) if "kw_security" in df.columns else False,
            "ssn": bool(df["kw_ssn"].values[0]) if "kw_ssn" in df.columns else False,
            "credit_card": bool(df["kw_credit card"].values[0]) if "kw_credit card" in df.columns else False,
        }
    }

    return jsonify({
        "prediction": "Phishing" if pred == 1 else "Legit",
        "probability": float(prob),
        "features": features_dict
    })


# ------------------ Advanced Analysis Routes ------------------

@app.route("/analyze_url_deep", methods=["POST"])
def analyze_url_deep():
    """Deep analysis of a single URL using external APIs"""
    url = request.form.get("url", "")
    
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    
    # Run comprehensive URL analysis
    analysis = URLAnalyzer.analyze_url_comprehensive(url)
    
    return jsonify(analysis)


@app.route("/analyze_ip", methods=["POST"])
def analyze_ip():
    """Analyze IP address reputation"""
    ip = request.form.get("ip", "")
    
    if not ip:
        return jsonify({"error": "No IP provided"}), 400
    
    # Run IP analysis
    analysis = IPAnalyzer.analyze_ip_comprehensive(ip)
    
    return jsonify(analysis)


@app.route("/analyze_domain", methods=["POST"])
def analyze_domain():
    """Analyze domain reputation and WHOIS"""
    domain = request.form.get("domain", "")
    
    if not domain:
        return jsonify({"error": "No domain provided"}), 400
    
    # Run domain analysis
    analysis = DomainAnalyzer.analyze_domain_comprehensive(domain)
    
    return jsonify(analysis)


@app.route("/analyze_email_deep", methods=["POST"])
def analyze_email_deep():
    """
    Deep analysis of email - extracts all URLs, IPs, domains
    and analyzes them with external APIs
    """
    raw_email = request.form.get("email", "")
    
    if not raw_email:
        return jsonify({"error": "No email content provided"}), 400
    
    # Extract features first
    features = extract_all_features(raw_email)
    
    # Extract URLs from email
    url_pattern = re.compile(r'https?://[^\s\'"<>]+', re.IGNORECASE)
    urls = url_pattern.findall(raw_email)
    
    # Extract IPs
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    ips = ip_pattern.findall(raw_email)
    
    # Extract domains from URLs
    domains = []
    for url in urls:
        try:
            parsed = urlparse(url)
            if parsed.netloc:
                domains.append(parsed.netloc)
        except:
            pass
    
    # Also add sender domain
    if features.get('from_domain'):
        domains.append(features['from_domain'])
    
    # Remove duplicates
    urls = list(set(urls))
    ips = list(set(ips))
    domains = list(set(domains))
    
    # Prepare data for analysis
    email_data = {
        "urls": urls[:5],  # Limit to 5 URLs to avoid rate limits
        "ips": ips[:5],
        "domains": domains[:5],
        "attachments": []  # File analysis would require actual file content
    }
    
    # Run comprehensive analysis
    analysis = analyze_email_components(email_data)
    
    # Add basic email features
    analysis['email_features'] = {
        "from_domain": features.get('from_domain'),
        "has_spf": features.get('has_spf'),
        "has_dkim": features.get('has_dkim'),
        "domain_mismatch": features.get('from_return_mismatch'),
        "num_urls": len(urls),
        "num_ips": len(ips),
        "num_domains": len(domains)
    }
    
    return jsonify(analysis)


@app.route("/advanced_analysis")
def advanced_analysis_page():
    """Render the advanced analysis page"""
    api_status = get_api_status()
    return render_template("advanced_analysis.html", api_status=api_status)


@app.route("/api_config", methods=["GET", "POST"])
def api_config():
    """Configure API keys"""
    if request.method == "POST":
        service = request.form.get("service")
        api_key = request.form.get("api_key")
        
        if set_api_key(service, api_key):
            return jsonify({"success": True, "message": f"{service} API key configured"})
        else:
            return jsonify({"success": False, "message": "Invalid service"}), 400
    
    # GET request - show current status
    return jsonify(get_api_status())


# ------------------ Run ------------------
if __name__ == "__main__":
    app.run(debug=True)
