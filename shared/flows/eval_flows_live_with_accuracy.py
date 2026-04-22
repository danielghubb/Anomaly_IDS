#!/usr/bin/env python3
"""
ML Flow Evaluation with Accuracy Tracking
Extended version of eval_flows_live.py that tracks ground truth vs predictions.

This script:
1. Reads live CICFlowMeter CSV
2. Predicts anomaly with Random Forest model
3. Labels flows with ground truth (from CSV labels file)
4. Tracks accuracy metrics (TP, FP, TN, FN)
5. Sends alerts to IRIS (with accuracy metadata)
6. Generates accuracy reports

Usage:
    python eval_flows_live_with_accuracy.py \\
        --csv /flows/live_flow_features.csv \\
        --model /shared/model/RandomForestModel.pkl \\
        --labels-file /shared/flows/ground_truth_labels.csv \\
        --accuracy-output /shared/flows/accuracy
"""

import argparse
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import original functionality
from eval_flows_live import *

# Import new accuracy modules
from ground_truth_labeler import GroundTruthLabeler
from accuracy_tracker import AccuracyTracker


def main_with_accuracy():
    """Main function with accuracy tracking integrated."""
    
    ap = argparse.ArgumentParser(
        description="ML Flow Evaluation with Accuracy Tracking"
    )
    
    # Original arguments
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
    ap.add_argument("--threshold", type=float, default=0.51,
                    help="Anomaly probability threshold (default: 0.51)")
    ap.add_argument("--poll", type=float, default=0.25,
                    help="Polling interval seconds (default: 0.25)")
    ap.add_argument("--state", default=None,
                    help="Optional state file to persist file offset")
    
    # New accuracy tracking arguments
    ap.add_argument("--labels-file", default="/shared/flows/ground_truth_labels.csv",
                    help="Path to ground truth labels CSV (default: /shared/flows/ground_truth_labels.csv)")
    ap.add_argument("--accuracy-output", default="/shared/flows/accuracy",
                    help="Directory for accuracy reports (default: /shared/flows/accuracy)")
    ap.add_argument("--enable-accuracy-tracking", action="store_true", default=True,
                    help="Enable accuracy tracking (default: True)")
    ap.add_argument("--accuracy-report-interval", type=int, default=100,
                    help="Generate accuracy report every N flows (default: 100)")
    ap.add_argument("--duration", type=int, default=None,
                    help="Run for N seconds then exit with final report (default: run indefinitely)")

    args = ap.parse_args()
    
    # Initialize IRIS session
    print(f"[{iso_utc_now()}] ========================================")
    print(f"[{iso_utc_now()}] ML Anomaly Detection with Accuracy Tracking")
    print(f"[{iso_utc_now()}] ========================================")
    
    iris_session = initialize_iris_session()
    if not iris_session:
        print("ERROR: Failed to initialize IRIS session. Exiting.", file=sys.stderr)
        sys.exit(1)
    
    # Load model
    with open(args.model, "rb") as f:
        model = pickle.load(f)
    
    if not hasattr(model, "feature_names_in_"):
        print("ERROR: Model has no feature_names_in_ -> cannot map safely.", file=sys.stderr)
        sys.exit(2)
    
    model_features = list(model.feature_names_in_)
    model_name = os.path.basename(args.model)
    
    # Initialize ground truth labeler
    labeler = GroundTruthLabeler(labels_file=args.labels_file)
    print(f"[{iso_utc_now()}] Ground truth labeler initialized")
    print(f"[{iso_utc_now()}] Labels file: {args.labels_file}")
    
    # Initialize accuracy tracker
    accuracy_tracker = AccuracyTracker(output_dir=args.accuracy_output)
    print(f"[{iso_utc_now()}] Accuracy tracker initialized")
    print(f"[{iso_utc_now()}] Output directory: {args.accuracy_output}")
    
    benign_class = detect_benign_class(model)
    benign_idx = None
    if benign_class is not None and hasattr(model, "classes_"):
        try:
            benign_idx = list(model.classes_).index(benign_class)
        except Exception:
            benign_idx = None
    
    # Offset state + CSV header handling
    offset = 0
    if args.state and os.path.exists(args.state):
        try:
            with open(args.state, "r", encoding="utf-8") as sf:
                offset = int(sf.read().strip() or "0")
        except Exception:
            offset = 0
    
    fieldnames: Optional[List[str]] = None
    
    # Case manager (alerts to IRIS)
    case_mgr = CaseManager(
        inactivity_seconds=int(args.case_inactivity),
        batch_size=args.case_batch_size,
        iris_session=iris_session,
        model_name=model_name,
        threshold=args.threshold
    )
    
    # Read header
    fieldnames = read_header_from_start(args.csv)
    if fieldnames is None:
        print(f"ERROR: Failed to read header from {args.csv}", file=sys.stderr)
        sys.exit(2)
    
    print(f"[{iso_utc_now()}] ========================================")
    print(f"[{iso_utc_now()}] Starting monitoring with accuracy tracking...")
    print(f"[{iso_utc_now()}] CSV: {args.csv}")
    print(f"[{iso_utc_now()}] Model: {args.model}")
    print(f"[{iso_utc_now()}] Threshold: {args.threshold}")
    print(f"[{iso_utc_now()}] Accuracy tracking: {args.enable_accuracy_tracking}")
    print(f"[{iso_utc_now()}] Report interval: {args.accuracy_report_interval} flows")
    if args.duration:
        print(f"[{iso_utc_now()}] Duration: {args.duration} seconds")
    print(f"[{iso_utc_now()}] ========================================")

    flows_processed = 0
    start_time = datetime.now(timezone.utc)

    while True:
        try:
            # Check if duration limit reached
            if args.duration is not None:
                elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
                if elapsed >= args.duration:
                    print(f"\n[{iso_utc_now()}] Duration limit reached ({args.duration}s)")
                    break

            if not os.path.exists(args.csv):
                case_mgr.flush_inactive(datetime.now(timezone.utc))
                time.sleep(args.poll)
                continue
            
            # Handle file truncation/rotation
            try:
                st = os.stat(args.csv)
                if st.st_size < offset:
                    offset = 0
                    fieldnames = None
            except Exception:
                pass
            
            new_offset = offset
            rows: List[dict] = []
            
            # Read new flows from CSV
            with open(args.csv, "r", encoding="utf-8", newline="") as f:
                if offset == 0:
                    header_line = f.readline()
                    if not header_line:
                        time.sleep(args.poll)
                        continue
                    fieldnames = next(csv.reader([header_line]))
                    offset = f.tell()
                    persist_offset(args.state, offset)
                
                f.seek(offset)
                reader = csv.reader(f)
                for row in reader:
                    if not row:
                        continue
                    d = dict(zip(fieldnames, row))
                    rows.append(d)
                
                new_offset = f.tell()
            
            if new_offset != offset:
                offset = new_offset
                persist_offset(args.state, offset)
            
            # Process each flow
            for flow in rows:
                flows_processed += 1
                
                # Extract flow metadata
                src_ip = flow.get("Src IP", "")
                dst_ip = flow.get("Dst IP", "")
                src_port_raw = flow.get("Src Port")
                dst_port_raw = flow.get("Dst Port")
                proto = protocol_to_name(flow.get("Protocol", flow.get("proto", "")))
                timestamp_str = flow.get("Timestamp", "")
                
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
                
                # Generate flow ID
                flow_id = f"{src_ip}_{dst_ip}_{src_port}_{dst_port}_{proto}"
                
                # --- GROUND TRUTH LABELING ---
                true_label, labeling_reason = labeler.label_flow(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    timestamp=None,  # Could parse timestamp_str if needed
                    flow_id=flow_id
                )
                
                # --- MODEL PREDICTION ---
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
                        proba = model.predict_proba(X)[0]
                        if benign_idx is not None and benign_idx < len(proba):
                            benign_p = float(proba[benign_idx])
                            anomaly_score = 1.0 - benign_p
                        else:
                            anomaly_score = float(np.max(proba))
                    except Exception:
                        anomaly_score = None
                
                # Determine if anomaly based on threshold
                if anomaly_score is not None:
                    is_anomaly = (anomaly_score >= args.threshold)
                else:
                    if benign_class is not None:
                        is_anomaly = (normalize_label(pred) != normalize_label(benign_class))
                    else:
                        is_anomaly = False
                
                # Map to BENIGN/MALICIOUS
                predicted_label = "MALICIOUS" if is_anomaly else "BENIGN"
                
                # --- ACCURACY TRACKING ---
                if args.enable_accuracy_tracking:
                    classification = accuracy_tracker.record_prediction(
                        flow_id=flow_id,
                        timestamp=iso_utc_now(),
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_port=src_port,
                        dst_port=dst_port,
                        proto=proto,
                        true_label=true_label,
                        labeling_reason=labeling_reason,
                        predicted_label=predicted_label,
                        anomaly_score=float(anomaly_score if anomaly_score is not None else 0.0),
                        threshold=args.threshold,
                        case_id=None,  # Will be set when alert is added to case
                        alert_id=None
                    )
                    
                    # Log classification
                    
                    print(
                        f"[{iso_utc_now()}] Flow {flows_processed}:  {classification} "
                        f"true={true_label} pred={predicted_label} score={anomaly_score:.4f} "
                        f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"
                    )
                
                # --- ALERT GENERATION (if anomaly detected) ---
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
                    
                    # Add accuracy metadata to alert
                    if args.enable_accuracy_tracking:
                        if "metadata" not in alert_event:
                            alert_event["metadata"] = {}
                        if "ml" not in alert_event["metadata"]:
                            alert_event["metadata"]["ml"] = {}
                        
                        alert_event["metadata"]["ml"]["ground_truth"] = {
                            "label": true_label,
                            "reason": labeling_reason,
                            "classification": classification
                        }
                    
                    case_mgr.add_alert(alert_event)
                
                # --- PERIODIC ACCURACY REPORTS ---
                if args.enable_accuracy_tracking and flows_processed % args.accuracy_report_interval == 0:
                    print(f"\n[{iso_utc_now()}] --- Accuracy Report (after {flows_processed} flows) ---")
                    accuracy_tracker.print_summary()
                    accuracy_tracker.save_summary_report()
            
            # Flush inactive cases
            case_mgr.flush_inactive(datetime.now(timezone.utc))
            time.sleep(args.poll)
        
        except KeyboardInterrupt:
            print(f"\n[{iso_utc_now()}] Shutdown signal received...")
            break
        
        except Exception as e:
            print(f"[{iso_utc_now()}] ERROR: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc()
            try:
                case_mgr.flush_inactive(datetime.now(timezone.utc))
            except Exception:
                pass
            time.sleep(max(args.poll, 1.0))

    # Final cleanup and reporting (reached via break or duration limit)
    if args.enable_accuracy_tracking:
        print(f"\n[{iso_utc_now()}] FINAL ACCURACY REPORT")
        accuracy_tracker.print_summary()
        accuracy_tracker.export_flow_predictions()
        accuracy_tracker.export_case_metrics()
        accuracy_tracker.export_confusion_matrix_csv()
        accuracy_tracker.save_summary_report()

    # Flush remaining cases
    try:
        case_mgr.flush_all()
    except Exception as e:
        print(f"[{iso_utc_now()}] ERROR during shutdown flush: {e}", file=sys.stderr)

    print(f"[{iso_utc_now()}] Stopped.")


if __name__ == "__main__":
    main_with_accuracy()
