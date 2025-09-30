from flask import Flask, request, render_template, jsonify
import joblib
import pandas as pd
import numpy as np
from scipy.sparse import hstack

# ------------------ Load Models ------------------
# URL model + preprocessing assets
url_model = joblib.load("URL_detection_model.pkl")
expected_columns = joblib.load("expected_columns.pkl")
top_tlds = joblib.load("top_tlds.pkl")

# Email model + preprocessing assets
email_assets = joblib.load("phish_detector_joblib.pkl")
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
    features = {
        "body": raw_email_str,
        "subj_len": 0,   # until you parse subject line
        "subj_words": 0,
        "body_len": len(raw_email_str),
        "body_words": len(raw_email_str.split()),
        "uppercase_ratio": sum(1 for c in raw_email_str if c.isupper()) / max(1, len(raw_email_str)),
        "exclaim_count": raw_email_str.count("!"),
        "question_count": raw_email_str.count("?"),
        "num_urls": raw_email_str.count("http"),
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
        "kw_verify": int("verify" in raw_email_str.lower()),
        "kw_password": int("password" in raw_email_str.lower()),
        "kw_account": int("account" in raw_email_str.lower()),
        "kw_urgent": int("urgent" in raw_email_str.lower()),
        "kw_click here": int("click here" in raw_email_str.lower()),
        "kw_bank": int("bank" in raw_email_str.lower()),
        "kw_login": int("login" in raw_email_str.lower()),
        "kw_update": int("update" in raw_email_str.lower()),
        "kw_suspend": int("suspend" in raw_email_str.lower()),
        "kw_confirm": int("confirm" in raw_email_str.lower()),
        "kw_security": int("security" in raw_email_str.lower()),
        "kw_ssn": int("ssn" in raw_email_str.lower()),
        "kw_credit card": int("credit card" in raw_email_str.lower()),
    }
    return pd.DataFrame([features])


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

    # Extract main features for response
    features_dict = {
        "body_length": int(df["body_len"].values[0]),
        "body_words": int(df["body_words"].values[0]),
        "uppercase_ratio": float(df["uppercase_ratio"].values[0]),
        "exclamation_marks": int(df["exclaim_count"].values[0]),
        "question_marks": int(df["question_count"].values[0]),
        "num_urls": int(df["num_urls"].values[0]),
        "num_attachments": int(df["num_attachments"].values[0]),
        "suspicious_keywords": {
            "verify": bool(df["kw_verify"].values[0]),
            "password": bool(df["kw_password"].values[0]),
            "account": bool(df["kw_account"].values[0]),
            "urgent": bool(df["kw_urgent"].values[0]),
            "click_here": bool(df["kw_click here"].values[0]),
            "bank": bool(df["kw_bank"].values[0]),
            "login": bool(df["kw_login"].values[0]),
            "update": bool(df["kw_update"].values[0]),
            "suspend": bool(df["kw_suspend"].values[0]),
            "confirm": bool(df["kw_confirm"].values[0]),
            "security": bool(df["kw_security"].values[0]),
            "ssn": bool(df["kw_ssn"].values[0]),
            "credit_card": bool(df["kw_credit card"].values[0]),
        }
    }

    return jsonify({
        "prediction": "Phishing" if pred == 1 else "Legit",
        "probability": float(prob),
        "features": features_dict
    })


# ------------------ Run ------------------
if __name__ == "__main__":
    app.run(debug=True)
