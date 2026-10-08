"""Stage 5: Flask glue. Flow: form -> extract() -> model -> explain() -> save -> show.

Routes:
  GET  /        -> check form
  POST /predict -> JSON {verdict, confidence, explanation}
  GET  /history -> last 20 verdicts (audit trail)

Run: python app.py -> open http://127.0.0.1:5000
"""
import joblib
import numpy as np
from flask import Flask, request, jsonify, render_template

from config import FEATURE_COLUMNS, RF_PATH, LR_PATH, MAX_URL_LENGTH
from feature_extractor import URLFeatureExtractor
from explainer import explain
import database

app = Flask(__name__)
extractor = URLFeatureExtractor()
models = {}


def load_models():
    global models
    for name, path in [("random_forest", RF_PATH), ("logistic_regression", LR_PATH)]:
        try:
            models[name] = joblib.load(path)
            print(f"Loaded {name}")
        except FileNotFoundError:
            print(f"Missing {path} — run: python train_model.py")


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json(force=True, silent=True) or {}
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "URL is required"}), 400
    if len(url) > MAX_URL_LENGTH:
        return jsonify({"error": "URL too long"}), 400
    if "://" not in url and "." not in url:
        return jsonify({"error": "Invalid URL format"}), 400

    feats = extractor.extract(url)
    vec = np.array([[feats[c] for c in FEATURE_COLUMNS]])
    name = "random_forest" if "random_forest" in models else "logistic_regression"
    proba = models[name].predict_proba(vec)[0]
    mal_prob = float(proba[1])
    is_mal = mal_prob > 0.5
    conf = mal_prob if is_mal else float(proba[0])

    exp = explain(feats, is_mal, conf)
    database.save(url, exp["verdict"], round(conf * 100, 2), exp["summary"])
    return jsonify({"url": url, "verdict": exp["verdict"],
                    "confidence": round(conf * 100, 2),
                    "model_used": name, "explanation": exp})


@app.route("/history")
def history():
    return render_template("history.html", predictions=database.recent())


if __name__ == "__main__":
    database.init_db()
    load_models()
    app.run(host="127.0.0.1", port=5000, debug=True)
