from __future__ import annotations
from typing import Iterable, Optional, Dict, Any, List
import os

def available_interfaces_pyshark() -> list[str]:
    try:
        import pyshark
        return pyshark.tshark.tshark.get_tshark_interfaces()
    except Exception:
        return []

def iter_live_packets(interface: str, bpf_filter: Optional[str]=None):
    import pyshark
    cap = pyshark.LiveCapture(interface=interface, bpf_filter=bpf_filter)
    for pkt in cap.sniff_continuously():
        yield pkt

def iter_pcap(path: str):
    import pyshark
    cap = pyshark.FileCapture(path, keep_packets=False)
    for pkt in cap:
        yield pkt
