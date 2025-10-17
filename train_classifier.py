import pandas as pd
from pathlib import Path
from app.model import train_protocol_classifier, save_model


def main(csv_path: str, out_model: str="protocol_rf.joblib"):
    df = pd.read_csv(csv_path)
    clf, metrics = train_protocol_classifier(df)
    save_model(clf, out_model)
    print("Saved model to", out_model)
    print("Report:", metrics["report"])

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True, help="Path to input CSV")
    ap.add_argument("--out", default="protocol_rf.joblib", help="Where to save model")
    args = ap.parse_args()
    main(args.csv, args.out)
