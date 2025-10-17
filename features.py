from __future__ import annotations
import pandas as pd
import numpy as np
from typing import Optional, Dict, Any

TCP_FLAG_FIELDS = ["fin", "syn", "rst", "psh", "ack", "urg", "ece", "cwr"]

def _safe_int(x):
    try:
        return int(x)
    except Exception:
        return np.nan

def extract_from_pyshark_packet(pkt, last_ts: Optional[float]) -> Dict[str, Any]:
    # Timestamps / IAT
    ts = float(getattr(pkt, "sniff_timestamp", np.nan)) if hasattr(pkt, "sniff_timestamp") else np.nan
    iat = ts - last_ts if (last_ts is not None and not np.isnan(ts)) else np.nan

    # IPs and ports
    src_ip = getattr(getattr(pkt, "ip", None), "src", None) or getattr(getattr(pkt, "ipv6", None), "src", None)
    dst_ip = getattr(getattr(pkt, "ip", None), "dst", None) or getattr(getattr(pkt, "ipv6", None), "dst", None)

    # Ports
    src_port = _safe_int(getattr(getattr(pkt, "tcp", None), "srcport", None) or getattr(getattr(pkt, "udp", None), "srcport", None))
    dst_port = _safe_int(getattr(getattr(pkt, "tcp", None), "dstport", None) or getattr(getattr(pkt, "udp", None), "dstport", None))

    length = _safe_int(getattr(pkt, "length", None) or getattr(pkt, "len", None))

    # TCP flags (0/1)
    flags = {f"tcp_flag_{f}": 0 for f in TCP_FLAG_FIELDS}
    if hasattr(pkt, "tcp"):
        for f in TCP_FLAG_FIELDS:
            flags[f"tcp_flag_{f}"] = int(bool(getattr(pkt.tcp, f, 0)))

    highest = getattr(pkt, "highest_layer", None)
    proto_num = np.nan
    if hasattr(pkt, "ip"):
        proto_num = _safe_int(getattr(pkt.ip, "proto", None))

    row = {
        "timestamp": ts,
        "iat": iat,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "length": length,
        "ip_proto": proto_num,
        "highest_layer": highest,
    }
    row.update(flags)
    return row

NUMERIC_FEATURES = ["iat", "src_port", "dst_port", "length", "ip_proto"] + [f"tcp_flag_{f}" for f in TCP_FLAG_FIELDS]

def preprocess(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()
    for c in NUMERIC_FEATURES:
        if c not in out.columns:
            out[c] = np.nan
    # Fill NaNs with 0 for model input
    out[NUMERIC_FEATURES] = out[NUMERIC_FEATURES].fillna(0)
    return out
