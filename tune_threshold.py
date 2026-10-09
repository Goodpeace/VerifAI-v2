"""Pick the operating threshold WITHOUT peeking at the test set (non-sloppy).

Method: single stratified 80/20 split of TRAIN ONLY (train+val + host-only
augmentation, same as train_model.py --full), fit the exact production
config, scan thresholds, pick lowest with FPR <= 0.5%.
Writes models/threshold.json. Test set stays untouched for final reporting.

Why single split instead of 5-fold OOF: identical procedure, ~7.8k validation
rows (plenty for a 0.5% FPR estimate), but 1 fit instead of 5 - fits in a
512MB build container where 5 parallel RF fits OOM. Seed fixed => reproducible.
"""
import json
import os
import numpy as np
import pandas as pd
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

from config import DATA_PATH, MODEL_DIR
from train_model import extract_matrix

TARGET_FPR = 0.005


def main():
    path = os.path.join(os.path.dirname(DATA_PATH), "urls_labelled.csv")
    df = pd.read_csv(path)
    base = pd.concat([df[df["split"] == "train"], df[df["split"] == "val"]]).reset_index(drop=True)
    urls = list(base["url"])
    y = list(base["label"].values)
    for u, lab in zip(list(urls), list(y)):
        try:
            p = urlparse(str(u).lower().strip())
            if p.hostname and (p.path.strip("/") or p.query):
                urls.append(f"{p.scheme or 'https'}://{p.hostname}")
                y.append(lab)
        except Exception:
            pass
    y = np.array(y)
    print(f"Tuning on {len(y)} train rows (test untouched)")
    X = np.array(extract_matrix(urls))

    Xa, Xv, ya, yv = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    rf = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=2)
    rf.fit(Xa, ya)
    v = rf.predict_proba(Xv)[:, 1]
    best = None
    print("thr   FPR      recall   prec")
    for thr in [0.50, 0.55, 0.60, 0.65, 0.70, 0.75, 0.80, 0.85, 0.90, 0.95]:
        pred = (v >= thr).astype(int)
        fp = int(((pred == 1) & (yv == 0)).sum())
        tn = int(((pred == 0) & (yv == 0)).sum())
        tp = int(((pred == 1) & (yv == 1)).sum())
        fn = int(((pred == 0) & (yv == 1)).sum())
        fpr = fp / (fp + tn)
        rec = tp / (tp + fn) if (tp + fn) else 0
        prec = tp / (tp + fp) if (tp + fp) else 0
        print(f"{thr:.2f}  {fpr:.4f}   {rec:.4f}   {prec:.4f}")
        if fpr <= TARGET_FPR and best is None:
            best = (thr, fpr, rec, prec)
    if best is None:
        best = (0.95, fpr, rec, prec)
        print("0.5% FPR not reachable by threshold alone - taking 0.95; "
              "residual FPs go to the Uncertain review band + host signals (Phase 2)")
    thr, fpr, rec, prec = best
    os.makedirs(MODEL_DIR, exist_ok=True)
    with open(os.path.join(MODEL_DIR, "threshold.json"), "w") as f:
        json.dump({"threshold": thr, "target_fpr": TARGET_FPR,
                   "val_fpr": fpr, "val_recall": rec, "val_precision": prec,
                   "method": "single-80/20-split-train-only-seed-42"}, f, indent=2)
    print(f"Saved threshold={thr} (val FPR={fpr:.4f}, recall={rec:.4f})")


if __name__ == "__main__":
    main()
