from __future__ import annotations
import pandas as pd
import numpy as np
from typing import Tuple, Optional
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.preprocessing import LabelEncoder
import joblib

from app.features import NUMERIC_FEATURES, preprocess
from app.utils import normalize_protocol

CLASSES = ["HTTP","HTTPS","DNS","FTP","SMTP","TCP","UDP","OTHER"]

def add_labels(df: pd.DataFrame) -> pd.DataFrame:
    # Map to coarse protocol class using highest_layer or ports
    protocols = []
    for _, r in df.iterrows():
        label = normalize_protocol(str(r.get("highest_layer", "")), r.get("src_port"), r.get("dst_port"))
        protocols.append(label)
    df = df.copy()
    df["label"] = protocols
    return df

def train_protocol_classifier(df: pd.DataFrame, test_size: float=0.25, random_state: int=42) -> Tuple[RandomForestClassifier, dict]:
    df = add_labels(df)
    X = preprocess(df)[NUMERIC_FEATURES]
    y = df["label"].astype(str)

    le = LabelEncoder()
    y_enc = le.fit_transform(y)

    X_train, X_test, y_train, y_test = train_test_split(X, y_enc, stratify=y_enc, test_size=test_size, random_state=random_state)
    clf = RandomForestClassifier(n_estimators=200, max_depth=None, n_jobs=-1, random_state=random_state)
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    report = classification_report(y_test, y_pred, target_names=le.classes_, output_dict=True, zero_division=0)
    cm = confusion_matrix(y_test, y_pred).tolist()

    # Multi-class ROC AUC (ovo)
    try:
        proba = clf.predict_proba(X_test)
        auc = roc_auc_score(y_test, proba, multi_class="ovo")
    except Exception:
        auc = None

    metrics = {"report": report, "confusion_matrix": cm, "classes": le.classes_.tolist(), "roc_auc_ovo": auc}
    return clf, metrics

def save_model(clf, path: str):
    joblib.dump(clf, path)

def load_model(path: str):
    return joblib.load(path)
