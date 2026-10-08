"""VerifAI-v2 config — one place for all paths and constants.

WHY this file exists: your original repo scattered magic strings
("models/xgboost.joblib", feature lists, rate limits) inside app.py
and train_model.py. If you rename a file, you must hunt 3 places.
Here you change it once.
"""
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

MODEL_DIR = os.path.join(BASE_DIR, "models")
DATA_PATH = os.path.join(BASE_DIR, "data", "sample_urls.csv")
DB_PATH = os.path.join(BASE_DIR, "verifai.db")

RF_PATH = os.path.join(MODEL_DIR, "random_forest.joblib")
LR_PATH = os.path.join(MODEL_DIR, "logistic_regression.joblib")

# The ONLY features v2 uses. Original had 21 (12 lexical + 5 host + 4 ratio).
# v2 starts with 10 lexical-only so you can learn without WHOIS/DNS pain.
# Host-based (domain_age, DNS) is Stage 4 in docs/.
FEATURE_COLUMNS = [
    "url_length",
    "domain_length",
    "path_length",
    "dot_count",
    "hyphen_count",
    "digit_count",
    "special_char_count",
    "has_ip_address",
    "has_at_symbol",
    "has_https",
]

MAX_URL_LENGTH = 2048
