# detector.py
import os, joblib, numpy as np
from features import extract_features

MODEL_PATH = os.getenv("DETECTOR_MODEL", "models/detector.joblib")
LABELS = ["caesar", "vigenere"]
_clf = joblib.load(MODEL_PATH)

def detect_with_model(ct: str):
    x = np.array(extract_features(ct)).reshape(1, -1)
    proba = _clf.predict_proba(x)[0]
    k = int(proba.argmax())
    return LABELS[k], float(proba[k])
