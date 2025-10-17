from __future__ import annotations
import streamlit as st
import pandas as pd
import numpy as np
from collections import deque
import plotly.express as px
import time
import os

from utils import normalize_protocol, now_ms
from features import extract_from_pyshark_packet, preprocess, NUMERIC_FEATURES
from capture import available_interfaces_pyshark, iter_live_packets, iter_pcap
from model import train_protocol_classifier, add_labels, save_model, load_model
from anomaly import fit_isolation_forest, score_anomaly

st.set_page_config(page_title="Network Traffic Analyzer", layout="wide")

st.title("🔎 Network Traffic Analyzer — ML + Real‑Time Dashboard")

mode = st.sidebar.selectbox("Mode", ["Live Capture", "PCAP Upload", "CSV Upload"])
state = st.session_state

if "df" not in state:
    state.df = pd.DataFrame()

def draw_overview(df: pd.DataFrame):
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Packets", f"{len(df):,}")
    c2.metric("Unique Sources", df["src_ip"].nunique() if "src_ip" in df else 0)
    c3.metric("Unique Destinations", df["dst_ip"].nunique() if "dst_ip" in df else 0)
    c4.metric("Median Size (B)", int(df["length"].median()) if "length" in df and not df["length"].empty else 0)

    if not df.empty:
        protos = add_labels(df)["label"]
        fig = px.histogram(protos, title="Protocol Distribution")
        st.plotly_chart(fig, use_container_width=True)

        if "timestamp" in df:
            tmp = df.copy()
            tmp["time"] = pd.to_datetime(tmp["timestamp"], unit="s", errors="coerce")
            series = tmp.set_index("time").resample("1S")["length"].count().fillna(0)
            fig2 = px.line(series, title="Packets per Second")
            st.plotly_chart(fig2, use_container_width=True)

def run_training_and_anomaly(df: pd.DataFrame):
    with st.spinner("Training protocol classifier on current dataset..."):
        clf, metrics = train_protocol_classifier(df)
    st.success("Classifier trained.")
    st.write("**Classification report:**")
    st.json(metrics["report"])
    st.write("**Confusion matrix (rows=true, cols=pred):**")
    st.write(pd.DataFrame(metrics["confusion_matrix"], index=metrics["classes"], columns=metrics["classes"]))

    with st.spinner("Fitting IsolationForest for anomaly detection..."):
        iso = fit_isolation_forest(df)
    st.success("Anomaly model fitted.")

    scores, labels = score_anomaly(iso, df)
    out = df.copy()
    out["anomaly_score"] = scores
    out["is_anomaly"] = (labels == -1)
    st.write("**Anomaly samples (top 10 by severity):**")
    st.dataframe(out.sort_values("anomaly_score").head(10))

if mode == "Live Capture":
    st.info("Requires TShark/Wireshark installed and proper privileges.")
    ifaces = available_interfaces_pyshark()
    iface = st.selectbox("Interface", options=ifaces)
    bpf = st.text_input("BPF filter (optional)", value="")

    capturing = st.toggle("Start capture")
    if capturing and iface:
        buf = []
        last_ts = None
        placeholder = st.empty()
        start_time = time.time()
        for i, pkt in enumerate(iter_live_packets(iface, bpf)):
            row = extract_from_pyshark_packet(pkt, last_ts)
            last_ts = row["timestamp"]
            buf.append(row)
            if len(buf) >= 100:
                chunk = pd.DataFrame(buf)
                state.df = pd.concat([state.df, chunk], ignore_index=True)
                buf.clear()

            if (i % 50) == 0:
                with placeholder.container():
                    st.subheader("Live Overview")
                    draw_overview(state.df)
            # Safety stop after 2 minutes if user forgets
            if time.time() - start_time > 120:
                st.warning("Auto-stopped after 120s to conserve resources. Toggle again to continue.")
                break

    if not state.df.empty:
        st.divider()
        st.subheader("Modeling on captured data")
        run_training_and_anomaly(state.df)

elif mode == "PCAP Upload":
    up = st.file_uploader("Upload .pcap/.pcapng", type=["pcap","pcapng"])
    if up is not None:
        with open("tmp_upload.pcap", "wb") as f:
            f.write(up.read())
        st.success("PCAP uploaded. Parsing...")
        rows = []
        last_ts = None
        for pkt in iter_pcap("tmp_upload.pcap"):
            row = extract_from_pyshark_packet(pkt, last_ts)
            last_ts = row["timestamp"]
            rows.append(row)
        df = pd.DataFrame(rows)
        state.df = df
        st.success(f"Parsed {len(df)} packets.")
        draw_overview(df)

        st.divider()
        st.subheader("Modeling on uploaded PCAP")
        run_training_and_anomaly(df)

elif mode == "CSV Upload":
    st.write("Upload a CSV conforming to the schema (see `data/schema.csv`).")
    up = st.file_uploader("Upload CSV", type=["csv"])
    if up is not None:
        df = pd.read_csv(up)
        state.df = df
        st.success(f"Loaded {len(df)} rows.")
        draw_overview(df)

        st.divider()
        st.subheader("Modeling on uploaded CSV")
        run_training_and_anomaly(df)

st.sidebar.markdown("---")
