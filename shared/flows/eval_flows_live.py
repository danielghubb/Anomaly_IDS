#!/usr/bin/env python3
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
from dfir_iris_client.case import Case
from dfir_iris_client.alert import Alert

# Suppress SSL warnings for self-signed certificates in lab environment
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


from feature_mapping import CIC_TO_MODEL_MAP
from helper_functions import *


# -----------------------------
# Case aggregation (Case-Events)
# -----------------------------

@dataclass
class CaseBucket:
    src_ip: str
    dest_ip: str
    proto: Optional[str] = None
    geo_src: Optional[str] = None
    geo_dst: Optional[str] = None
    entries: List[dict] = field(default_factory=list)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    case_id: Optional[str] = None

    def add(self, alert_event: dict) -> None:
        ts = parse_iso_z(alert_event["timestamp"])
        if self.first_seen is None:
            self.first_seen = ts
        self.last_seen = ts
        self.entries.append(alert_event)

    def is_inactive(self, now: datetime, inactivity_timeout: timedelta) -> bool:
        if self.last_seen is None:
            return False
        return (now - self.last_seen) >= inactivity_timeout

    def summarize(self) -> dict:
        scores: List[float] = []
        signatures: Dict[str, int] = {}
        protos: Dict[str, int] = {}
        dports: Dict[str, int] = {}
        sport_dport_pairs: Dict[str, int] = {}

        for e in self.entries:
            md = e.get("metadata", {}) or {}
            sc = md.get("anomaly_score")
            if sc is None:
                sc = (md.get("ml", {}) or {}).get("anomaly_score")

            if isinstance(sc, (int, float)):
                scores.append(float(sc))


            sig = (e.get("alert", {}) or {}).get("signature", "unknown")
            signatures[sig] = signatures.get(sig, 0) + 1

            p = e.get("proto")
            if p:
                protos[p] = protos.get(p, 0) + 1

            dp = e.get("dest_port")
            if dp is not None:
                dp_s = str(dp)
                dports[dp_s] = dports.get(dp_s, 0) + 1

            sp = e.get("src_port")
            if sp is not None and dp is not None:
                key = f"{sp}->{dp}"
                sport_dport_pairs[key] = sport_dport_pairs.get(key, 0) + 1

        def top_k(d: Dict[str, int], k: int = 5):
            return sorted(d.items(), key=lambda x: (-x[1], x[0]))[:k]

        return {
            "src_ip": self.src_ip,
            "dest_ip": self.dest_ip,
            "proto": self.proto,
            "count": len(self.entries),
            "first_seen": self.first_seen.isoformat().replace("+00:00", "Z") if self.first_seen else None,
            "last_seen": self.last_seen.isoformat().replace("+00:00", "Z") if self.last_seen else None,
            "anomaly_score_avg": (sum(scores) / len(scores)) if scores else None,
            "anomaly_score_max": max(scores) if scores else None,
            "top_signatures": top_k(signatures, 5),
            "top_protos": top_k(protos, 5),
            "top_dest_ports": top_k(dports, 5),
            "top_srcdst_ports": top_k(sport_dport_pairs, 5),
        }


class CaseManager:
    """
    Groups ML alert events into cases by (src_ip, dest_ip).
    A case is flushed when it has been inactive for inactivity_seconds
    """
    def __init__(
        self,
        inactivity_seconds: int = 120,
        batch_size: int = 20,
        iris_session: Optional[ClientSession] = None,
        model_name: str = "ML Model",
        threshold: float = 0.5,
        host_aliases_csv: str = "/shared/flows/host_aliases.csv",
        ip_country_csv: str = "/shared/flows/ip_country_dummy.csv"
    ):
        self.buckets: Dict[Tuple[str, str], CaseBucket] = {}
        self.inactivity_timeout = timedelta(seconds=inactivity_seconds)
        self.batch_size = batch_size
        self.iris_session = iris_session
        self.model_name = model_name
        self.threshold = threshold
        self.host_aliases = load_host_aliases_map(host_aliases_csv)
        self.ip_ranges = load_ip_range_locations(ip_country_csv)

    def _create_iris_case(self, src_ip: str, dest_ip: str, first_seen: datetime) -> Optional[int]:
        if not self.iris_session:
            print(
                f"[{iso_utc_now()}] WARNING: No IRIS session available, cannot create case", file=sys.stderr)
            return None

        try:
            case_name = f"ML anomalies: {src_ip} -> {dest_ip} {first_seen.strftime('%Y-%m-%d %H:%M:%S')}"
            case_soc_id = f"ML-{src_ip}-{dest_ip}-{first_seen.strftime('%Y%m%d-%H%M%S')}"
            geo_src = resolve_geolocation(src_ip, self.host_aliases, self.ip_ranges)
            geo_dst = resolve_geolocation(dest_ip, self.host_aliases, self.ip_ranges)
            case_description = f"""Machine Learning Anomaly Detection Case

**Flow:**
- Source IP: {src_ip}
- Geolocation Source IP: {geo_src}
- Destination IP: {dest_ip}
- Geolocation Destination IP: {geo_dst}
- First Seen: {first_seen.isoformat()}
- Last Seen: {first_seen.isoformat()}

**Detection:**
- Model: {self.model_name}
- Threshold: {self.threshold}

**Scanned Destination Ports:**
- Count: 0
- Ports: (none)

This case aggregates ML-detected anomalies for this specific network flow.
Alerts are batched (batch size: {self.batch_size}) to reduce noise."""

            case_client = Case(session=self.iris_session)
            result = case_client.add_case(
                case_name=case_name,
                case_description=case_description,
                case_customer=1,
                case_classification=1,  # Default classification
                soc_id=case_soc_id
            )

            if result.is_success():
                case_id = result.get_data().get('case_id')
                print(
                    f"[{iso_utc_now()}] Created IRIS case #{case_id}: {case_name}")
                return case_id
            else:
                print(
                    f"[{iso_utc_now()}] ERROR: Failed to create IRIS case: {result.get_msg()}", file=sys.stderr)
                return None

        except Exception as e:
            print(
                f"[{iso_utc_now()}] ERROR: Exception creating IRIS case: {e}", file=sys.stderr)
            return None
        

    def _update_summary(self, case_id: int, bucket: CaseBucket) -> bool:
        if not self.iris_session or not case_id:
            return False

        now_iso = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")

        try:
            case_client = Case(session=self.iris_session)

            res = case_client.get_summary(cid=case_id)
            if not res.is_success():
                print(f"[{iso_utc_now()}] ERROR: get_summary failed for case #{case_id}: {res.get_msg()}", file=sys.stderr)
                return False

            data = res.get_data()

            # try to get summary
            if isinstance(data, str):
                summary_text = data
            elif isinstance(data, dict):
                summary_text = (data.get("case_description") or data.get("summary") or data.get("data") or "")
            else:
                summary_text = ""

            summary_text = (summary_text or "").strip()

            # replace Last Seen
            pattern = r"(?m)^\s*-?\s*Last\s+Seen\s*:\s*.*$"
            replacement = f"- Last Seen: {now_iso}"

            if re.search(pattern, summary_text):
                updated = re.sub(pattern, replacement, summary_text)
            else:
                # if Last Seen not existent, append it
                first_seen_pat = r"(?m)^\s*-?\s*First\s+Seen\s*:\s*.*$"
                if re.search(first_seen_pat, summary_text):
                    updated = re.sub(first_seen_pat, lambda m: m.group(0) + "\n" + replacement, summary_text, count=1)
                else:
                    updated = summary_text + "\n" + replacement


            #Extract existing ports from current summary text
            existing_ports = set()
            ports_block_pattern = r"\*\*Scanned Destination Ports:\*\*[\s\S]*?(?=\n\n|\Z)"
            ports_line_pattern = r"(?m)^\s*-\s*Ports\s*:\s*(.*)\s*$"

            m_block = re.search(ports_block_pattern, updated)
            if m_block:
                m_ports_line = re.search(ports_line_pattern, m_block.group(0))
                if m_ports_line:
                    ports_raw = m_ports_line.group(1)
                    for p in ports_raw.split(","):
                        p = p.strip()
                        if p.isdigit():
                            existing_ports.add(int(p))

            #Merge with ports from current bucket
            new_ports = extract_unique_dest_ports_from_bucket(bucket)
            all_ports = sorted(existing_ports.union(new_ports))

            #Build the updated block
            ports_block = (
                "**Scanned Destination Ports:**\n"
                f"- Count: {len(all_ports)}\n"
                f"- Ports: {', '.join(str(p) for p in all_ports)}"
            )

            #Replace existing block or append
            if re.search(ports_block_pattern, updated):
                updated = re.sub(ports_block_pattern, ports_block, updated)
            else:
                updated = updated.strip() + "\n\n" + ports_block


            upd = case_client.set_summary(summary_content=updated, cid=case_id)
            if not upd.is_success():
                print(f"[{iso_utc_now()}] ERROR: set_summary failed for case #{case_id}: {upd.get_msg()}", file=sys.stderr)
                return False

            return True

        except Exception as e:
            print(f"[{iso_utc_now()}] ERROR: Exception updating summary Last Seen for case #{case_id}: {e}", file=sys.stderr)
            return False
        



    def _send_summary_to_iris(self, bucket: CaseBucket) -> bool:
        if not self.iris_session or not bucket.case_id or len(bucket.entries) == 0:
            return False

        try:
            summary = bucket.summarize()
            count = summary["count"]

            per_alert_port_pairs = []
            for e in bucket.entries:
                sp = e.get("src_port")
                dp = e.get("dest_port")
                sp_s = str(sp) if sp is not None else "N/A"
                dp_s = str(dp) if dp is not None else "N/A"
                per_alert_port_pairs.append(f"{sp_s} --> {dp_s}")

            alert_title = f"ML batch anomaly ({count} alerts): {bucket.src_ip} -> {bucket.dest_ip}"

            # Build human-readable description
            desc_lines = [
                f"**Batch Summary: {count} ML anomalies detected**",
                "",
                f"**Network Flow:**",
                f"- Source IP: {bucket.src_ip}",
                f"- Source Geolocation: {bucket.geo_src}",
                f"- Destination IP: {bucket.dest_ip}",
                f"- Destination Geolocation: {bucket.geo_dst}",
                f"- Protocol: {bucket.proto or 'N/A'}",
                "",
                f"**Time Window:**",
                f"- First Seen: {summary['first_seen']}",
                f"- Last Seen: {summary['last_seen']}",
                "",
                f"**Anomaly Scores:**",
                f"- Average: {summary['anomaly_score_avg']:.4f}" if summary.get('anomaly_score_avg') is not None else "- Average: N/A",
                f"- Maximum: {summary['anomaly_score_max']:.4f}" if summary.get('anomaly_score_max') is not None else "- Maximum: N/A",
            ]

            desc_lines.append("")
            desc_lines.append("**Alert Port Pairs:**")
            for i, e in enumerate(bucket.entries, start=1):
                sp = e.get("src_port")
                dp = e.get("dest_port")

                # Make sure we always create something readable
                sp_s = str(sp) if sp is not None else "N/A"
                dp_s = str(dp) if dp is not None else "N/A"

                desc_lines.append(f"- Alert {i}: {sp_s} --> {dp_s}")


            # Add top signatures
            if summary['top_signatures']:
                desc_lines.append("")
                desc_lines.append("**Top Attack Signatures:**")
                for sig, cnt in summary['top_signatures']:
                    desc_lines.append(f"- {sig}: {cnt}x")

            # Add top destination ports
            if summary['top_dest_ports']:
                desc_lines.append("")
                desc_lines.append("**Top Destination Ports:**")
                for port, cnt in summary['top_dest_ports']:
                    desc_lines.append(f"- Port {port}: {cnt}x")

            # Add top port pairs
            if summary['top_srcdst_ports']:
                desc_lines.append("")
                desc_lines.append("**Top Source->Dest Port Pairs:**")
                for pair, cnt in summary['top_srcdst_ports']:
                    desc_lines.append(f"- {pair}: {cnt}x")

            alert_description = "\n".join(desc_lines)

            # Create alert in IRIS using the Alert client
            alert_client = Alert(session=self.iris_session)

            sample_alerts = bucket.entries[:5] if len(
                bucket.entries) > 5 else bucket.entries

            # EVE-like summary alert event (batch)
            eve_summary_event = {
                "timestamp": iso_utc_now(),
                "flow_id": make_eve_flow_id(bucket.src_ip, bucket.dest_ip, None, None, bucket.proto or ""),
                "event_type": "alert",
                "src_ip": bucket.src_ip,
                "dest_ip": bucket.dest_ip,
                "geoip": {
                    "src": bucket.geo_src,
                    "dst": bucket.geo_dst,
                },
                "proto": bucket.proto or "N/A",
                "alert": {
                    "action": "allowed",
                    "gid": 1,
                    "signature_id": 50364013,
                    "rev": 1,
                    "signature": f"ML batch anomaly ({count} alerts)",
                    "category": "Anomaly Detection",
                    "severity": 2,
                },
                "metadata": {
                    "ml": {
                        "bucket_count": count,
                        "first_seen": summary["first_seen"],
                        "last_seen": summary["last_seen"],
                        "anomaly_score_avg": summary["anomaly_score_avg"],
                        "anomaly_score_max": summary["anomaly_score_max"],
                        "geolocation_src": bucket.geo_src,
                        "geolocation_dst": bucket.geo_dst,
                        "per_alert_port_pairs": per_alert_port_pairs,  # <-- Punkt (3)
                        "top_signatures": summary.get("top_signatures", []),
                        "top_dest_ports": summary.get("top_dest_ports", []),
                    }
                }
            }

            alert_data = {
                "alert_title": alert_title,
                "alert_description": alert_description,
                "alert_source": "ML Anomaly Detection",
                "alert_severity_id": 2,  # Medium severity
                "alert_status_id": 2,
                "alert_source_content": {
                    "eve_summary_event": eve_summary_event,
                    "eve_sample_alerts": sample_alerts,
                },
                "alert_tags": f"ml,anomaly,batch-{count}",
                "alert_customer_id": 1
            }

            # Step 1: Create the alert
            result = alert_client.add_alert(alert_data=alert_data)

            if not result.is_success():
                print(
                    f"[{iso_utc_now()}] ERROR: Failed to create alert in IRIS: {result.get_msg()}", file=sys.stderr)
                return False

            alert_id = result.get_data().get('alert_id')
            if not alert_id:
                print(
                    f"[{iso_utc_now()}] ERROR: Alert created but no alert_id returned", file=sys.stderr)
                return False

            # Step 2: Merge the alert into the case
            merge_note = f"ML batch anomaly summary: {count} anomalies detected for {bucket.src_ip} -> {bucket.dest_ip}"
            merge_result = alert_client.merge_alert(
                alert_id=alert_id,
                target_case_id=bucket.case_id,
                iocs_import_list=[],  # No IOCs to import
                assets_import_list=[],  # No assets to import
                merge_note=merge_note,
                import_as_event=True  # Import as event in the case timeline
            )

            if merge_result.is_success():
                self._update_summary(case_id=int(bucket.case_id), bucket=bucket)
                print(
                    f"[{iso_utc_now()}] Created alert #{alert_id} and merged into IRIS case #{bucket.case_id}: {count} anomalies")
                return True
            else:
                print(
                    f"[{iso_utc_now()}] ERROR: Alert #{alert_id} created but failed to merge into case #{bucket.case_id}: {merge_result.get_msg()}", file=sys.stderr)
                return False

        except Exception as e:
            print(
                f"[{iso_utc_now()}] ERROR: Exception sending summary to IRIS: {e}", file=sys.stderr)
            return False

    def add_alert(self, alert_event: dict) -> None:
        src = alert_event.get("src_ip")
        dst = alert_event.get("dest_ip")
        proto = alert_event.get("proto")
        if not src or not dst:
            return

        # Filter: Only process alerts involving 10.0.0.x network
        if not should_process_alert(src, dst):
            return

        key = (src, dst)

        if key not in self.buckets:
            geo_src = resolve_geolocation(src, self.host_aliases, self.ip_ranges)
            geo_dst = resolve_geolocation(dst, self.host_aliases, self.ip_ranges)
            bucket = CaseBucket(src_ip=src, dest_ip=dst, proto=proto, geo_src=geo_src, geo_dst=geo_dst)
            ts = parse_iso_z(alert_event["timestamp"])
            case_id = self._create_iris_case(src, dst, ts)
            bucket.case_id = case_id
            self.buckets[key] = bucket

        self.buckets[key].add(alert_event)

        # Check if we've reached batch size
        if len(self.buckets[key].entries) >= self.batch_size:
            print(
                f"[{iso_utc_now()}] Batch size ({self.batch_size}) reached for {src} -> {dst}, sending summary to IRIS")
            self._send_summary_to_iris(self.buckets[key])
            # Clear the entries but keep the bucket (and case_id) open for future alerts
            self.buckets[key].entries.clear()

    def flush_inactive(self, now: datetime) -> None:
        for key, bucket in list(self.buckets.items()):
            if bucket.is_inactive(now, self.inactivity_timeout):
                # Send any remaining alerts to IRIS before removing bucket
                if len(bucket.entries) > 0:
                    print(
                        f"[{iso_utc_now()}] Flushing inactive bucket {bucket.src_ip} -> {bucket.dest_ip} ({len(bucket.entries)} pending alerts)")
                    self._send_summary_to_iris(bucket)
                del self.buckets[key]

    def flush_all(self) -> None:
        for bucket in self.buckets.values():
            if len(bucket.entries) > 0:
                print(
                    f"[{iso_utc_now()}] Shutdown: flushing bucket {bucket.src_ip} -> {bucket.dest_ip} ({len(bucket.entries)} pending alerts)")
                self._send_summary_to_iris(bucket)
        self.buckets.clear()



def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True,
                    help="Path to live-updated flows CSV")
    ap.add_argument("--model", required=True,
                    help="Path to RandomForestModel.pkl")
    ap.add_argument("--case-inactivity", type=int, default=120,
                    help="Flush case after N seconds without new alerts (default: 120)")
    ap.add_argument("--case-batch-size", type=int, default=20,
                    help="Number of alerts to batch before sending to IRIS (default: 20)")
    ap.add_argument("--severity", type=int, default=2,
                    help="Alert severity (1=high ... 4=low, default: 2)")
    ap.add_argument("--threshold", type=float, default=0.5,
                    help="Anomaly probability threshold (default: 0.5)")
    ap.add_argument("--poll", type=float, default=0.25,
                    help="Polling interval seconds (default: 0.25)")
    ap.add_argument("--state", default=None,
                    help="Optional state file to persist file offset")
    args = ap.parse_args()

    iris_session = initialize_iris_session()
    if not iris_session:
        print("ERROR: Failed to initialize IRIS session. Exiting.", file=sys.stderr)
        sys.exit(1)

    with open(args.model, "rb") as f:
        model = pickle.load(f)

    if not hasattr(model, "feature_names_in_"):
        print(
            "ERROR: Model has no feature_names_in_ -> cannot map safely.", file=sys.stderr)
        sys.exit(2)

    model_features = list(model.feature_names_in_)
    model_name = os.path.basename(args.model)

    benign_class = detect_benign_class(model)
    benign_idx = None
    if benign_class is not None and hasattr(model, "classes_"):
        try:
            benign_idx = list(model.classes_).index(benign_class)
        except Exception:
            benign_idx = None

    # we read flows from CSV starting at this offset
    offset = 0
    if args.state and os.path.exists(args.state):
        try:
            with open(args.state, "r", encoding="utf-8") as sf:
                offset = int(sf.read().strip() or "0")
        except Exception:
            offset = 0

    # Store CSV header (featurenames) independently of offset.
    fieldnames: Optional[List[str]] = None

    case_mgr = CaseManager(
        inactivity_seconds=int(args.case_inactivity),
        batch_size=args.case_batch_size,
        iris_session=iris_session,
        model_name=model_name,
        threshold=args.threshold
    )

    # Ensure we have fieldnames (header) at startup, even if offset > 0 (restart scenario)
    fieldnames = read_header_from_start(args.csv)
    if fieldnames is None:
        print(f"ERROR: Failed to read header from {args.csv}", file=sys.stderr)
        sys.exit(2)

    print(f"[{iso_utc_now()}] Starting monitoring...")
    print(f"[{iso_utc_now()}] CSV: {args.csv}")
    print(f"[{iso_utc_now()}] Model: {args.model}")
    print(f"[{iso_utc_now()}] Batch size: {args.case_batch_size}")
    print(f"[{iso_utc_now()}] Inactivity timeout: {args.case_inactivity}s")
    print(f"[{iso_utc_now()}] Threshold: {args.threshold}")
    print(f"[{iso_utc_now()}] ========================================")

    while True:
        try:
            if not os.path.exists(args.csv):
                case_mgr.flush_inactive(datetime.now(timezone.utc))
                time.sleep(args.poll)
                continue

            # handle truncation/rotation: if file shrunk, reset offset and re-read header
            try:
                st = os.stat(args.csv)
                if st.st_size < offset:
                    offset = 0
                    fieldnames = None
            except Exception:
                pass

            new_offset = offset
            rows: List[dict] = []

            with open(args.csv, "r", encoding="utf-8", newline="") as f:
                # If starting fresh (offset == 0), consume header line once and set offset behind it.
                if offset == 0:
                    header_line = f.readline()
                    if not header_line:
                        time.sleep(args.poll)
                        continue
                    # Always trust the actual header line on fresh start/rotation
                    fieldnames = next(csv.reader([header_line]))
                    offset = f.tell()
                    persist_offset(args.state, offset)

                # Read new data lines from current offset
                f.seek(offset)
                reader = csv.reader(f)
                for row in reader:
                    if not row:
                        continue
                    # robust zip (extra columns ignored; missing columns absent)
                    d = dict(zip(fieldnames, row))
                    rows.append(d)

                new_offset = f.tell()

            if new_offset != offset:
                offset = new_offset
                persist_offset(args.state, offset)

            # Process newly read rows
            for flow in rows:
                # Build model input and predict
                mapped_flow = map_cic_to_model(flow, model_features)
                X = build_X(mapped_flow, model_features)

                try:
                    pred = model.predict(X)[0]
                except Exception:
                    pred = "UNKNOWN"

                anomaly_score = None
                benign_p = None

                if hasattr(model, "predict_proba"):
                    try:
                        proba = model.predict_proba(X)[0]  # shape (n_classes,)
                        if benign_idx is not None and benign_idx < len(proba):
                            benign_p = float(proba[benign_idx])
                            anomaly_score = 1.0 - benign_p
                        else:
                            anomaly_score = float(np.max(proba))
                    except Exception:
                        anomaly_score = None

                # Determine anomaly
                if anomaly_score is not None:
                    is_anomaly = (anomaly_score >= args.threshold)
                else:
                    if benign_class is not None:
                        is_anomaly = (normalize_label(pred) !=
                                      normalize_label(benign_class))
                    else:
                        is_anomaly = False

                if is_anomaly:
                    alert_event = build_alert_event(
                        flow,
                        str(pred),
                        float(anomaly_score if anomaly_score is not None else 0.0),
                        args.model,
                        model,
                        args.severity,
                        args.threshold,
                        benign_p,
                    )
                    case_mgr.add_alert(alert_event)

                    print(
                        f"[{iso_utc_now()}] ALERT: pred={pred} anomaly_score={anomaly_score:.4f} benign_p={benign_p} "
                        f"src={alert_event.get('src_ip')} dst={alert_event.get('dest_ip')}"
                    )

            # Flush inactive cases (also when no new anomalies arrived)
            case_mgr.flush_inactive(datetime.now(timezone.utc))
            time.sleep(args.poll)

        except KeyboardInterrupt:
            # best-effort flush all remaining open cases on shutdown
            print(
                f"\n[{iso_utc_now()}] Shutdown signal received, flushing remaining alerts...")
            try:
                case_mgr.flush_all()
            except Exception as e:
                print(
                    f"[{iso_utc_now()}] ERROR during shutdown flush: {e}", file=sys.stderr)
            print(f"[{iso_utc_now()}] Stopped.")
            return

        except Exception as e:
            print(f"[{iso_utc_now()}] ERROR: {e}", file=sys.stderr)
            try:
                case_mgr.flush_inactive(datetime.now(timezone.utc))
            except Exception:
                pass
            time.sleep(max(args.poll, 1.0))


if __name__ == "__main__":
    main()
