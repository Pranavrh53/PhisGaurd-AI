from flask import Flask, request, render_template
import joblib
import pandas as pd

# Load model + preprocessing assets
model = joblib.load("URL_detection_model.pkl")
expected_columns = joblib.load("expected_columns.pkl")
top_tlds = joblib.load("top_tlds.pkl")

app = Flask(__name__)

# ----- Feature Extraction Function -----
def extract_features(url):
    """
    This should match the preprocessing logic from your notebook.
    For now, I'll give a simple example based on top_tlds & length.
    You’ll need to extend this with the exact feature extraction steps you used.
    """
    features = {}

    # Example features (replace with your real ones):
    features["url_length"] = len(url)
    features["num_dots"] = url.count(".")

    # Example: check if URL ends with one of your top_tlds
    for tld in top_tlds:
        features[f"tld_{tld}"] = 1 if url.endswith(tld) else 0

    # Convert dict → DataFrame
    df = pd.DataFrame([features])

    # Align columns with expected model input
    df = df.reindex(columns=expected_columns, fill_value=0)
    return df


@app.route("/", methods=["GET", "POST"])
def index():
    prediction_result = None
    if request.method == "POST":
        url = request.form["url"]

        # Extract features
        X = extract_features(url)

        # Predict probabilities
        probabilities = model.predict_proba(X)[0]
        benign_prob = probabilities[0]
        malicious_prob = probabilities[1]

        # Get prediction
        prediction = "Benign" if benign_prob > malicious_prob else "Malicious"

        prediction_result = {
            "url": url,
            "prediction": prediction,
            "prob_benign": f"{benign_prob:.2f}",
            "prob_malicious": f"{malicious_prob:.2f}",
        }

    return render_template("index.html", prediction_result=prediction_result)


if __name__ == "__main__":
    app.run(debug=True)
