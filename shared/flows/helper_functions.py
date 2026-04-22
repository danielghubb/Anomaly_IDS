import argparse
import csv
import json
import os
import sys
import time
import pickle
import pandas as pd
import numpy as np
import urllib3
import ipaddress
import re
from datetime import datetime, timezone
import hashlib

from dataclasses import dataclass, field
from typing import Dict, Tuple, List, Optional
from datetime import datetime, timezone, timedelta

from dfir_iris_client.session import ClientSession
from feature_mapping import CIC_TO_MODEL_MAP





def iso_utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_iso_z(ts: str) -> datetime:
    # expects e.g. 2025-12-16T14:02:10.962Z
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def protocol_to_name(proto_val):
    if proto_val is None:
        return ""
    s = str(proto_val).strip()
    if s == "":
        return ""
    if any(ch.isalpha() for ch in s):
        return s.upper()

    try:
        p = int(float(s))
        if p == 6:
            return "TCP"
        if p == 17:
            return "UDP"
        if p == 1:
            return "ICMP"
        return str(p)
    except Exception:
        return s


def safe_float(x, default=0.0):
    if x is None:
        return default
    s = str(x).strip()
    if s == "" or s.lower() in {"nan", "none", "null", "inf", "-inf"}:
        return default
    try:
        return float(s)
    except Exception:
        return default


def normalize_label(x):
    try:
        if isinstance(x, (np.integer, int)):
            return int(x)
        if isinstance(x, (np.floating, float)):
            return int(x)
    except Exception:
        pass
    return str(x).strip()


def detect_benign_class(model):
    if not hasattr(model, "classes_"):
        return None

    classes = list(model.classes_)

    for c in classes:
        if str(c).strip().upper() == "BENIGN":
            return c

    for c in classes:
        try:
            if int(c) == 0:
                return c
        except Exception:
            continue

    return None


def is_in_10_0_0_network(ip: str) -> bool:
    if not ip:
        return False
    try:
        # Parse IP address
        parts = str(ip).strip().split('.')
        if len(parts) != 4:
            return False

        # Check if it's in 10.0.0.0/24 network
        if parts[0] == '10' and parts[1] == '0' and parts[2] == '0':
            return True

        return False
    except Exception:
        return False


def should_process_alert(src_ip: str, dest_ip: str) -> bool:
    return is_in_10_0_0_network(src_ip) or is_in_10_0_0_network(dest_ip)


def extract_unique_dest_ports_from_bucket(bucket) -> List[int]:
    ports = set()
    for e in getattr(bucket, "entries", []) or []:
        dp = e.get("dest_port")
        if isinstance(dp, int):
            ports.add(dp)
    return sorted(ports)



# -----------------------------
# Methods for Enrichment
# -----------------------------

def _ip_to_int(ip: str) -> Optional[int]:
    try:
        return int(ipaddress.ip_address(str(ip).strip()))
    except Exception:
        return None


def load_host_aliases_map(csv_path: str) -> Dict[str, str]:
    # host_aliases.csv expected columns: ip,label
    m: Dict[str, str] = {}
    try:
        with open(csv_path, "r", encoding="utf-8", newline="") as f:
            rdr = csv.DictReader(f)
            for row in rdr:
                ip = (row.get("ip") or "").strip()
                label = (row.get("label") or "").strip()
                if ip and label:
                    m[ip] = label
    except Exception:
        pass
    return m


def load_ip_range_locations(csv_path: str) -> List[Tuple[int, int, str]]:
    # ip_country_dummy.csv expected columns: ip_start,ip_end,location
    ranges: List[Tuple[int, int, str]] = []
    try:
        with open(csv_path, "r", encoding="utf-8", newline="") as f:
            rdr = csv.DictReader(f)
            for row in rdr:
                s = (row.get("ip_start") or "").strip()
                e = (row.get("ip_end") or "").strip()
                loc = (row.get("location") or "").strip()
                if not (s and e and loc):
                    continue
                s_i = _ip_to_int(s)
                e_i = _ip_to_int(e)
                if s_i is None or e_i is None:
                    continue
                if s_i > e_i:
                    s_i, e_i = e_i, s_i
                ranges.append((s_i, e_i, loc))
    except Exception:
        pass

    # Optional: Sort for faster linear scan / future binary search
    ranges.sort(key=lambda x: x[0])
    return ranges


def resolve_geolocation(
    ip: str,
    host_aliases: Dict[str, str],
    ip_ranges: List[Tuple[int, int, str]],
) -> str:
    """
    1) Exact match in host_aliases: returns label (e.g., 'dodo')
    2) Else range match in ip_ranges: returns location (e.g., 'United States')
    3) Else 'Unknown'
    """
    if not ip:
        return "Unknown"

    ip_s = str(ip).strip()

    # 1) exact alias
    alias = host_aliases.get(ip_s)
    if alias:
        return alias

    # 2) range lookup
    ip_i = _ip_to_int(ip_s)
    if ip_i is None:
        return "Unknown"

    # linear scan is fine for small CSVs; for large files consider binary search
    for start_i, end_i, loc in ip_ranges:
        if start_i <= ip_i <= end_i:
            return loc

    return "Unknown"



def make_eve_flow_id(src_ip: str, dst_ip: str, src_port: Optional[int], dst_port: Optional[int], proto: str) -> int:
    # Suricata EVE uses a numeric flow_id (uint64-like). We generate a stable 64-bit integer from the 5-tuple.
    key = f"{src_ip}|{dst_ip}|{src_port or 0}|{dst_port or 0}|{proto or ''}"
    h = hashlib.blake2b(key.encode("utf-8"), digest_size=8).digest()  # 64-bit
    return int.from_bytes(h, byteorder="big", signed=False)




# -----------------------------
# Methods for Main Loop
# -----------------------------

def persist_offset(state_file: Optional[str], val: int) -> None:
    if not state_file:
        return
    try:
        with open(state_file, "w", encoding="utf-8") as sf:
            sf.write(str(val))
    except Exception:
        pass


def read_header_from_start(csv_path: str) -> Optional[List[str]]:
    try:
        with open(csv_path, "r", encoding="utf-8", newline="") as f0:
            header_line = f0.readline()
            if not header_line:
                return None
            return next(csv.reader([header_line]))
    except Exception:
        return None


def build_X(flow: dict, model_features: List[str]) -> pd.DataFrame:
    """
    Build a 1-row DataFrame for the model (uses model.feature_names_in_).
    Missing -> 0.0
    """
    df_row = pd.DataFrame([flow])
    X = df_row.reindex(columns=model_features, fill_value=0.0)

    for c in model_features:
        X[c] = X[c].map(lambda v: safe_float(v, 0.0))

    return X.astype(np.float32)


def map_cic_to_model(flow: dict, model_features: List[str]) -> dict:
    """
    Maps a CICFlowMeter CSV row to the model's expected feature names.
    Missing features are filled with 0.0.
    """
    mapped = {}

    # Rename known CIC columns
    for cic_name, model_name in CIC_TO_MODEL_MAP.items():
        if cic_name in flow:
            mapped[model_name] = flow.get(cic_name)

    # Handle duplicated feature expected by some models
    if 'FwdHeaderLength.1' in model_features:
        mapped['FwdHeaderLength.1'] = mapped.get('FwdHeaderLength', 0.0)

    # Ensure all model features exist
    for f in model_features:
        if f not in mapped:
            mapped[f] = 0.0
    return mapped


def build_alert_event(
    flow: dict,
    pred_label: str,
    anomaly_score: float,
    model_path: str,
    model,
    severity: int,
    threshold: float,
    benign_p: float = None
) -> dict:

    proto_name = protocol_to_name(
        flow.get("Protocol", flow.get("proto", "")))

    src_ip = flow.get("Src IP")
    dst_ip = flow.get("Dst IP")
    src_port_raw = flow.get("Src Port")
    dst_port_raw = flow.get("Dst Port")

    def to_int_or_none(v):
        s = str(v).strip() if v is not None else ""
        if s == "":
            return None
        try:
            return int(float(s))
        except Exception:
            return None

    src_port = to_int_or_none(src_port_raw)
    dst_port = to_int_or_none(dst_port_raw)

    #flow_id = f"{src_ip}-{dst_ip}-{src_port}-{dst_port}-{proto_name}"
    flow_id = make_eve_flow_id(src_ip, dst_ip, src_port, dst_port, proto_name)

    model_features = list(model.feature_names_in_)
    mapped_flow = map_cic_to_model(flow, model_features)
    X = build_X(mapped_flow, model_features)
    amount_top_features = 10
    if hasattr(model, "feature_importances_"):
        importances = model.feature_importances_
        names = model.feature_names_in_

        ranked = sorted(
            zip(names, importances),
            key=lambda x: x[1],
            reverse=True
        )[:amount_top_features]

        top_features_meta = [
            {
                "feature": fname,
                "importance": float(imp),
                # all values are int or float -> value
                "value": safe_float(mapped_flow.get(fname, 0.0))
            }
            for fname, imp in ranked
        ]
    else:
        top_features_meta = []

    alert_obj = {
        "timestamp": iso_utc_now(),
        "event_type": "alert",
        "flow_id": flow_id,
        "src_ip": src_ip,
        "src_port": src_port,
        "dest_ip": dst_ip,
        "dest_port": dst_port,
        "proto": proto_name,
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": 50364013,
            "rev": 1,
            "signature": f"ML Anomaly: {pred_label}",
            "category": "Anomaly Detection",
            "severity": int(severity),
        },
        "metadata": {
            "ml": {
                "model": os.path.basename(model_path),
                "threshold": float(threshold),
                "anomaly_score": float(anomaly_score),
                "benign_probability": float(benign_p) if benign_p is not None else None,
                "csv_timestamp": str(flow.get("Timestamp", flow.get("timestamp", "")) or ""),
                "classes": list(getattr(model, "classes_", [])),
                "top_" + str(amount_top_features) + "_features": top_features_meta
            }
        },
    }

    return alert_obj


def initialize_iris_session() -> Optional[ClientSession]:
    iris_url = "https://10.0.0.6"
    # Get API key from environment or use lab default
    iris_api_key = os.environ.get(
        "IRIS_API_KEY",
        "B8BA5D730210B50F41C06941582D7965D57319D5685440587F98DFDC45A01594"
    )

    print(f"[{iso_utc_now()}] Initializing IRIS session...")
    print(f"[{iso_utc_now()}] IRIS URL: {iris_url}")

    try:
        session = ClientSession(
            apikey=iris_api_key,
            host=iris_url,
            ssl_verify=False
        )
        print(f"[{iso_utc_now()}] IRIS session initialized successfully")
        return session
    except Exception as e:
        print(
            f"[{iso_utc_now()}] ERROR: Failed to initialize IRIS session: {e}", file=sys.stderr)
        return None

