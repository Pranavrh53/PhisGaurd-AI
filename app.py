from flask import Flask, request, render_template, jsonify, redirect, url_for
import joblib
import re
import pandas as pd
import numpy as np
from scipy.sparse import hstack
from email_features import extract_all_features
from explanation_handler import ExplanationHandler
from advanced_analysis import (
    URLAnalyzer, IPAnalyzer, DomainAnalyzer, FileAnalyzer, DeepEmailAnalyzer,
    analyze_email_components, get_api_status, set_api_key
)

# Initialize the deep email analyzer
deep_analyzer = DeepEmailAnalyzer()
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
explanation_handler = ExplanationHandler()

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
    
    # Convert the dictionary to a DataFrame and return it
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
    print("\n=== DEBUG: analyze_email_deep called ===")
    print(f"Request form data: {request.form}")
    print(f"Request files: {request.files}")
    
    raw_email = ""
    
    # Check for file upload first
    if 'file' in request.files:
        file = request.files.get('file')
        print(f"File object: {file}")
        if file and file.filename != '':
            print(f"Processing file: {file.filename}")
            try:
                raw_email = file.read().decode('utf-8', errors='ignore')
                print(f"Successfully read {len(raw_email)} bytes from file")
            except Exception as e:
                error_msg = f"Error reading file: {str(e)}"
                print(error_msg)
                return jsonify({"error": error_msg}), 400
    
    # If no file or file read failed, try to get text from form
    if not raw_email:
        print("No file or empty file, checking form data...")
        raw_email = request.form.get("email", "").strip()
        print(f"Got email from form: {'Yes' if raw_email else 'No'}")
    
    if not raw_email:
        error_msg = "No email content provided. Please either upload a file or paste the email content."
        print(error_msg)
        return jsonify({"error": error_msg}), 400
    print(f"Processing email with {len(raw_email)} characters")
    
    try:
        # Extract features first
        print("Extracting features from email...")
        try:
            features = extract_all_features(raw_email)
            print("Feature extraction completed successfully")
        except Exception as e:
            error_msg = f"Error in extract_all_features: {str(e)}"
            print(error_msg)
            import traceback
            traceback.print_exc()
            return jsonify({"error": error_msg}), 500
        
        # Extract URLs from email
        print("Extracting URLs...")
        url_pattern = re.compile(r'https?://[^\s\'"<>]+', re.IGNORECASE)
        urls = url_pattern.findall(raw_email)
        
        # Extract IPs
        print("Extracting IPs...")
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        ips = ip_pattern.findall(raw_email)
        
        # Extract domains from URLs
        print("Extracting domains...")
        domains = []
        for url in urls:
            try:
                parsed = urlparse(url)
                if parsed.netloc:
                    domains.append(parsed.netloc)
            except Exception as e:
                print(f"Error parsing URL {url}: {str(e)}")
        
        # Also add sender domain if available
        if features and isinstance(features, dict) and features.get('from_domain'):
            domains.append(features['from_domain'])
        
        # Remove duplicates and limit the number of items to process
        urls = list(set(urls))[:5]  # Limit to 5 URLs to avoid rate limits
        ips = list(set(ips))[:5]
        domains = list(set(domains))[:5]
        
        print(f"Found {len(urls)} URLs, {len(ips)} IPs, and {len(domains)} domains for analysis")
        
        # Initialize analyzers
        print("Initializing analyzers...")
        try:
            url_analyzer = URLAnalyzer()
            ip_analyzer = IPAnalyzer()
            domain_analyzer = DomainAnalyzer()
        except Exception as e:
            error_msg = f"Error initializing analyzers: {str(e)}"
            print(error_msg)
            return jsonify({"error": error_msg}), 500
        
        # Analyze each component
        print("Starting analysis...")
        try:
            url_results = []
            ip_results = []
            domain_results = []
            
            # Analyze URLs
            for url in urls:
                try:
                    result = url_analyzer.analyze_url_comprehensive(url)
                    url_results.append(result)
                except Exception as e:
                    print(f"Error analyzing URL {url}: {str(e)}")
                    url_results.append({"url": url, "error": str(e)})
            
            # Analyze IPs
            for ip in ips:
                try:
                    result = ip_analyzer.analyze_ip_comprehensive(ip)
                    ip_results.append(result)
                except Exception as e:
                    print(f"Error analyzing IP {ip}: {str(e)}")
                    ip_results.append({"ip": ip, "error": str(e)})
            
            # Analyze domains
            for domain in domains:
                try:
                    result = domain_analyzer.analyze_domain_comprehensive(domain)
                    domain_results.append(result)
                except Exception as e:
                    print(f"Error analyzing domain {domain}: {str(e)}")
                    domain_results.append({"domain": domain, "error": str(e)})
            
            # Compile results in the format expected by the frontend
            print("Compiling results...")
            result = {
                'status': 'success',
                'email_features': {
                    'from_domain': features.get('from_domain', ''),
                    'num_urls': len(urls),
                    'num_ips': len(ips),
                    'num_domains': len(domains)
                },
                'urls': url_results,
                'ips': ip_results,
                'domains': domain_results,
                'summary': {
                    'total_urls': len(urls),
                    'total_ips': len(ips),
                    'total_domains': len(domains),
                    'suspicious_count': (
                        sum(1 for r in url_results if isinstance(r, dict) and (r.get('is_malicious') or r.get('is_suspicious'))) +
                        sum(1 for r in ip_results if isinstance(r, dict) and (r.get('is_malicious') or r.get('is_suspicious'))) +
                        sum(1 for r in domain_results if isinstance(r, dict) and (r.get('is_malicious') or r.get('is_suspicious')))
                    )
                }
            }
            print("Analysis completed successfully")
            return jsonify(result)
            
        except Exception as e:
            error_msg = f"Error during analysis: {str(e)}"
            print(error_msg)
            import traceback
            traceback.print_exc()
            return jsonify({"error": error_msg}), 500

    except Exception as e:
        error_msg = f"Unexpected error in analyze_email_deep: {str(e)}"
        print(error_msg)
        import traceback
        traceback.print_exc()
        return jsonify({
            "error": error_msg,
            "verdict": "error",
            "is_malicious": False
        }), 500

@app.route("/advanced_analysis")
def advanced_analysis_page():
    """Render the advanced analysis page"""
    api_status = get_api_status()
    return render_template("advanced_analysis.html", api_status=api_status)


@app.route("/analyze_ai", methods=["POST"])
def analyze_ai():
    """Analyze email content for AI generation"""
    try:
        data = request.get_json()
        email_content = data.get('email', '').strip()
        
        if not email_content:
            return jsonify({"error": "No email content provided"}), 400
            
        # Use the DeepEmailAnalyzer to detect AI content
        ai_analysis = deep_analyzer.detect_ai_generated_content(email_content)
        
        return jsonify(ai_analysis)
        
    except Exception as e:
        return jsonify({"error": f"Error analyzing AI content: {str(e)}"}), 500

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