from __future__ import annotations
import enum
import re
import time
from typing import Optional

PROTO_MAP = {
    "HTTP": "HTTP",
    "TLS": "HTTPS",
    "SSL": "HTTPS",
    "DNS": "DNS",
    "FTP": "FTP",
    "SMTP": "SMTP",
    "TCP": "TCP",
    "UDP": "UDP",
}

COMMON_PORTS = {
    80: "HTTP",
    8080: "HTTP",
    8000: "HTTP",
    443: "HTTPS",
    53: "DNS",
    21: "FTP",
    20: "FTP",
    25: "SMTP",
    587: "SMTP",
    110: "POP3",
    143: "IMAP",
}

def normalize_protocol(highest_layer: Optional[str], src_port: Optional[int], dst_port: Optional[int]) -> str:
    hl = (highest_layer or "").upper()
    if hl in PROTO_MAP:
        return PROTO_MAP[hl]

    # Port-based fallback
    for p in (src_port, dst_port):
        if p in COMMON_PORTS:
            v = COMMON_PORTS[p]
            if v in ("HTTP","HTTPS","DNS","FTP","SMTP"):
                return v

    if hl in ("TCP", "UDP"):
        return hl
    return "OTHER"

def now_ms() -> int:
    return int(time.time() * 1000)
