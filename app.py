"""Stage 5: Flask glue. Flow: form -> extract() -> model -> explain() -> save -> show.

Routes:
  GET  /        -> check form
  POST /predict -> JSON {verdict, confidence, explanation}
  GET  /history -> last 20 verdicts (audit trail)
  GET  /health  -> {"status": "ok"} (Docker/Render health check)

Run dev:  python app.py -> open http://127.0.0.1:5000
Run prod: gunicorn app:app --bind 0.0.0.0:$PORT (Docker does this)
"""
import os
import joblib
import numpy as np
from urllib.parse import urlparse
from flask import Flask, request, jsonify, render_template

from config import FEATURE_COLUMNS, RF_PATH, LR_PATH, MAX_URL_LENGTH
from feature_extractor import URLFeatureExtractor
from explainer import explain
from host_intel import get_host_signals, adjust_with_host
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import database

app = Flask(__name__)
# Public demo protection: 30 requests/min per IP (same policy as thesis v1).
limiter = Limiter(get_remote_address, app=app, default_limits=["30 per minute"],
                  storage_uri="memory://")
extractor = URLFeatureExtractor()
models = {}


def load_models():
    global models
    for name, path in [("random_forest", RF_PATH), ("logistic_regression", LR_PATH)]:
        try:
            models[name] = joblib.load(path)
            print(f"Loaded {name}")
        except FileNotFoundError:
            print(f"Missing {path} - run: python train_model.py")


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/health")
def health():
    return jsonify({"status": "ok", "models_loaded": list(models.keys())})


@app.route("/predict", methods=["POST"])
@limiter.limit("30 per minute")
def predict():
    if not models:
        return jsonify({"error": "Models not trained yet. Run: python train_model.py --full"}), 503
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

    exp = explain(feats, mal_prob, rf_model=models.get("random_forest"))

    # Tier 2: host intel ONLY for the Uncertain band (~4% of traffic).
    # Confident verdicts are never flipped here - only annotated.
    tier2 = None
    if exp["verdict"] == "Uncertain":
        host = urlparse(("https://" + url) if "://" not in url else url).hostname or ""
        sig = get_host_signals(host)
        new_verdict, host_factors = adjust_with_host("Uncertain", mal_prob, sig)
        tier2 = {"host": host, "signals": sig, "escalated_to": new_verdict}
        if new_verdict != "Uncertain":
            exp["verdict"] = new_verdict
            exp["factors"].extend(host_factors)
            exp["summary"] += " Host-tier resolution: " + " ".join(
                f["reason"] for f in host_factors if f["feature"] != "host_lookup")
        else:
            exp["factors"].extend(host_factors)

    if exp["verdict"] == "Malicious":
        conf = mal_prob if tier2 is None or tier2["escalated_to"] == "Uncertain" else 0.75
    elif exp["verdict"] == "Legitimate":
        conf = 1 - mal_prob
    else:
        conf = mal_prob
    database.save(url, exp["verdict"], round(conf * 100, 2), exp["summary"])
    return jsonify({"url": url, "verdict": exp["verdict"],
                    "confidence": round(conf * 100, 2),
                    "model_used": name, "tier2": tier2, "explanation": exp})


@app.route("/history")
def history():
    return render_template("history.html", predictions=database.recent())


@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({"error": "Rate limit exceeded (30/min). Slow down - triage queues are human-paced."}), 429


# Load at import so gunicorn workers (which don't run __main__) have models.
database.init_db()
load_models()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "1") == "1"
    app.run(host="0.0.0.0", port=port, debug=debug)
