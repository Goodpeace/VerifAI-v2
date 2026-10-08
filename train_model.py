"""Stage 2: numbers + labels -> saved model file.

Run:  python train_model.py
Reads data/sample_urls.csv (20 rows), extracts 10 features each,
trains Logistic Regression (baseline) + Random Forest, prints accuracy,
saves to models/. app.py loads these files — no retraining at runtime.

For SOC jobs: you must be able to say "we split train/test, RF beat LR
because non-linear, we watch false-positive rate because blocking legit
bank = incident." Stage 3 (your 24k CSV) is where real metrics come from.
"""
import os
import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix

from config import DATA_PATH, MODEL_DIR, LR_PATH, RF_PATH, FEATURE_COLUMNS
from feature_extractor import URLFeatureExtractor


def main():
    df = pd.read_csv(DATA_PATH)
    print(f"Loaded {len(df)} URLs ({(df.label == 1).sum()} malicious)")

    ext = URLFeatureExtractor()
    X = [[ext.extract(u)[c] for c in FEATURE_COLUMNS] for u in df["url"]]
    y = df["label"].values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )

    models = {
        "logistic_regression": LogisticRegression(max_iter=1000),
        "random_forest": RandomForestClassifier(n_estimators=100, random_state=42),
    }
    os.makedirs(MODEL_DIR, exist_ok=True)
    for name, m in models.items():
        m.fit(X_train, y_train)
        pred = m.predict(X_test)
        acc = accuracy_score(y_test, pred)
        print(f"{name}: accuracy={acc:.2f} cm={confusion_matrix(y_test, pred).tolist()}")
        joblib.dump(m, LR_PATH if "logistic" in name else RF_PATH)
    print("Saved to models/. Now run: python app.py")


if __name__ == "__main__":
    main()
