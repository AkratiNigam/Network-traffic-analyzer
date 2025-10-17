from __future__ import annotations
import pandas as pd
from sklearn.ensemble import IsolationForest
from .features import NUMERIC_FEATURES, preprocess

def fit_isolation_forest(df: pd.DataFrame, contamination: float=0.03, random_state: int=42):
    X = preprocess(df)[NUMERIC_FEATURES]
    iso = IsolationForest(n_estimators=200, contamination=contamination, random_state=random_state)
    iso.fit(X)
    return iso

def score_anomaly(model, df: pd.DataFrame):
    X = preprocess(df)[NUMERIC_FEATURES]
    scores = model.decision_function(X)
    labels = model.predict(X)  # -1 anomaly, 1 normal
    return scores, labels
