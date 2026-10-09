"""Stage 2: numbers + labels -> saved model file.

Run:  python train_model.py            (20-row sample, 10 sec)
      python train_model.py --full    (24k thesis data, ~1-2 min, lexical-only)

Thesis used 21 features (needed WHOIS/DNS). v2 uses 10 lexical-only,
so expect ~1-3 pts below thesis 98.5%. Deliberate tradeoff: <1ms,
no internet, learnable. app.py loads these files - no retraining at runtime.
"""
import argparse
import os
import joblib
import pandas as pd
from urllib.parse import urlparse
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, confusion_matrix, precision_score, recall_score, f1_score,
)

from config import DATA_PATH, MODEL_DIR, LR_PATH, RF_PATH, FEATURE_COLUMNS
from feature_extractor import URLFeatureExtractor


def extract_matrix(urls):
    ext = URLFeatureExtractor()
    return [[ext.extract(u)[c] for c in FEATURE_COLUMNS] for u in urls]


def report(name, y_test, pred):
    tn, fp, fn, tp = confusion_matrix(y_test, pred).ravel()
    fpr = fp / (fp + tn) if (fp + tn) else 0
    print(f"{name}: acc={accuracy_score(y_test, pred):.4f} "
          f"prec={precision_score(y_test, pred, zero_division=0):.4f} "
          f"rec={recall_score(y_test, pred, zero_division=0):.4f} "
          f"f1={f1_score(y_test, pred, zero_division=0):.4f} "
          f"FPR={fpr:.4f} cm=[[TN={tn} FP={fp}] [FN={fn} TP={tp}]]")


def main(full: bool = False):
    if full:
        path = os.path.join(os.path.dirname(DATA_PATH), "urls_labelled.csv")
        df = pd.read_csv(path)
        print(f"Loaded {len(df)} URLs ({(df.label == 1).sum()} malicious)")
        train_df = df[df["split"] == "train"]
        val_df = df[df["split"] == "val"]
        test_df = df[df["split"] == "test"]
        print(f"Train: {len(train_df)}, Val->train: {len(val_df)}, Test: {len(test_df)}")
        train_df = pd.concat([train_df, val_df])
        # Augment TRAIN ONLY (never test): host-only variant of every URL
        # with a path, same label. Teaches the model that "google.com" and
        # "https://www.google.com/long/article" share one verdict - judges
        # the host, not the path length. This fixes shortened-URL bias.
        aug_urls, aug_labels = [], []
        for u, y in zip(train_df["url"], train_df["label"]):
            try:
                p = urlparse(str(u).lower().strip())
                if p.hostname and (p.path.strip("/") or p.query):
                    aug_urls.append(f"{p.scheme or 'https'}://{p.hostname}")
                    aug_labels.append(y)
            except Exception:
                pass
        print(f"Augmented train with {len(aug_urls)} host-only variants")
        X_train, y_train = extract_matrix(train_df["url"]), train_df["label"].values
        if aug_urls:
            X_train = X_train + extract_matrix(aug_urls)
            y_train = list(y_train) + aug_labels
        X_test, y_test = extract_matrix(test_df["url"]), test_df["label"].values
    else:
        df = pd.read_csv(DATA_PATH)
        print(f"Loaded {len(df)} URLs ({(df.label == 1).sum()} malicious)")
        X = extract_matrix(df["url"])
        y = df["label"].values
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.3, random_state=42, stratify=y
        )

    models = {
        "logistic_regression": LogisticRegression(max_iter=1000),
        "random_forest": RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1),
    }
    os.makedirs(MODEL_DIR, exist_ok=True)
    for name, m in models.items():
        m.fit(X_train, y_train)
        report(name, y_test, m.predict(X_test))
        joblib.dump(m, LR_PATH if "logistic" in name else RF_PATH)
    print("Saved to models/. Now run: python app.py")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--full", action="store_true", help="train on 24k urls_labelled.csv")
    main(full=ap.parse_args().full)
