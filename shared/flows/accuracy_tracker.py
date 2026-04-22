#!/usr/bin/env python3
"""
Accuracy Tracker
Tracks model predictions vs ground truth labels and calculates metrics.
Provides per-flow and per-case accuracy measurements.
"""

import json
import csv
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from pathlib import Path
import numpy as np


@dataclass
class FlowPrediction:
    """Record of a single flow prediction."""
    flow_id: str
    timestamp: str
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    proto: str
    
    # Ground truth
    true_label: str  # BENIGN or MALICIOUS
    labeling_reason: str  # Why this label was assigned
    
    # Model prediction
    predicted_label: str  # BENIGN or MALICIOUS
    anomaly_score: float
    threshold: float
    
    # Classification result
    is_correct: bool
    classification: str  # TP, TN, FP, FN
    
    # Optional: Case association
    case_id: Optional[str] = None
    alert_id: Optional[str] = None


@dataclass
class CaseMetrics:
    """Metrics for a single case (bucket of alerts)."""
    case_id: str
    src_ip: str
    dst_ip: str
    
    # Counts
    total_flows: int = 0
    tp_count: int = 0  # True Positives
    tn_count: int = 0  # True Negatives
    fp_count: int = 0  # False Positives
    fn_count: int = 0  # False Negatives
    
    # Aggregated scores
    avg_anomaly_score: float = 0.0
    max_anomaly_score: float = 0.0
    
    # Time window
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    
    def calculate_metrics(self) -> Dict[str, float]:
        """Calculate derived metrics from counts."""
        total = self.total_flows
        if total == 0:
            return {
                "accuracy": 0.0,
                "precision": 0.0,
                "recall": 0.0,
                "f1_score": 0.0,
                "fpr": 0.0,  # False Positive Rate
                "fnr": 0.0   # False Negative Rate
            }
        
        # Accuracy: (TP + TN) / Total
        accuracy = (self.tp_count + self.tn_count) / total if total > 0 else 0.0
        
        # Precision: TP / (TP + FP) - Of all predicted positives, how many are correct?
        precision = self.tp_count / (self.tp_count + self.fp_count) if (self.tp_count + self.fp_count) > 0 else 0.0
        
        # Recall (TPR): TP / (TP + FN) - Of all actual positives, how many did we catch?
        recall = self.tp_count / (self.tp_count + self.fn_count) if (self.tp_count + self.fn_count) > 0 else 0.0
        
        # F1 Score: Harmonic mean of precision and recall
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        
        # False Positive Rate: FP / (FP + TN) - Of all actual negatives, how many false alarms?
        fpr = self.fp_count / (self.fp_count + self.tn_count) if (self.fp_count + self.tn_count) > 0 else 0.0
        
        # False Negative Rate: FN / (FN + TP) - Of all actual positives, how many did we miss?
        fnr = self.fn_count / (self.fn_count + self.tp_count) if (self.fn_count + self.tp_count) > 0 else 0.0
        
        return {
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1_score": f1_score,
            "fpr": fpr,
            "fnr": fnr
        }


class AccuracyTracker:
    """
    Tracks predictions vs ground truth and calculates accuracy metrics.
    
    Maintains:
    - Per-flow predictions
    - Per-case aggregated metrics
    - Overall confusion matrix
    """
    
    def __init__(self, output_dir: str = "/shared/flows/accuracy"):
        """
        Initialize the accuracy tracker.
        
        Args:
            output_dir: Directory to save tracking data
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Storage
        self.flow_predictions: List[FlowPrediction] = []
        self.case_metrics: Dict[str, CaseMetrics] = {}  # case_id -> metrics
        
        # Overall confusion matrix
        self.tp_total = 0
        self.tn_total = 0
        self.fp_total = 0
        self.fn_total = 0
    
    def record_prediction(
        self,
        flow_id: str,
        timestamp: str,
        src_ip: str,
        dst_ip: str,
        src_port: Optional[int],
        dst_port: Optional[int],
        proto: str,
        true_label: str,
        labeling_reason: str,
        predicted_label: str,
        anomaly_score: float,
        threshold: float,
        case_id: Optional[str] = None,
        alert_id: Optional[str] = None
    ) -> str:
        """
        Record a single flow prediction.
        
        Returns:
            Classification: "TP", "TN", "FP", or "FN"
        """
        # Normalize labels
        true_label = true_label.upper()
        predicted_label = predicted_label.upper()
        
        # Determine classification
        is_correct = (true_label == predicted_label)
        
        if true_label == "MALICIOUS" and predicted_label == "MALICIOUS":
            classification = "TP"
            self.tp_total += 1
        elif true_label == "BENIGN" and predicted_label == "BENIGN":
            classification = "TN"
            self.tn_total += 1
        elif true_label == "BENIGN" and predicted_label == "MALICIOUS":
            classification = "FP"
            self.fp_total += 1
        elif true_label == "MALICIOUS" and predicted_label == "BENIGN":
            classification = "FN"
            self.fn_total += 1
        else:
            classification = "UNKNOWN"
        
        # Create prediction record
        pred = FlowPrediction(
            flow_id=flow_id,
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            proto=proto,
            true_label=true_label,
            labeling_reason=labeling_reason,
            predicted_label=predicted_label,
            anomaly_score=anomaly_score,
            threshold=threshold,
            is_correct=is_correct,
            classification=classification,
            case_id=case_id,
            alert_id=alert_id
        )
        
        self.flow_predictions.append(pred)
        
        # Update case metrics if associated with a case
        if case_id:
            self._update_case_metrics(case_id, src_ip, dst_ip, classification, anomaly_score, timestamp)
        
        return classification
    
    def _update_case_metrics(
        self,
        case_id: str,
        src_ip: str,
        dst_ip: str,
        classification: str,
        anomaly_score: float,
        timestamp: str
    ):
        """Update metrics for a specific case."""
        if case_id not in self.case_metrics:
            self.case_metrics[case_id] = CaseMetrics(
                case_id=case_id,
                src_ip=src_ip,
                dst_ip=dst_ip,
                first_seen=timestamp
            )
        
        metrics = self.case_metrics[case_id]
        metrics.total_flows += 1
        metrics.last_seen = timestamp
        
        # Update counts
        if classification == "TP":
            metrics.tp_count += 1
        elif classification == "TN":
            metrics.tn_count += 1
        elif classification == "FP":
            metrics.fp_count += 1
        elif classification == "FN":
            metrics.fn_count += 1
        
        # Update scores
        scores = [metrics.avg_anomaly_score] if metrics.avg_anomaly_score > 0 else []
        scores.append(anomaly_score)
        metrics.avg_anomaly_score = sum(scores) / len(scores)
        metrics.max_anomaly_score = max(metrics.max_anomaly_score, anomaly_score)
    
    def get_overall_metrics(self) -> Dict[str, float]:
        """Calculate overall metrics across all flows."""
        total = self.tp_total + self.tn_total + self.fp_total + self.fn_total
        
        if total == 0:
            return {
                "total_flows": 0,
                "accuracy": 0.0,
                "precision": 0.0,
                "recall": 0.0,
                "f1_score": 0.0,
                "fpr": 0.0,
                "fnr": 0.0,
                "tp": 0,
                "tn": 0,
                "fp": 0,
                "fn": 0
            }
        
        accuracy = (self.tp_total + self.tn_total) / total
        precision = self.tp_total / (self.tp_total + self.fp_total) if (self.tp_total + self.fp_total) > 0 else 0.0
        recall = self.tp_total / (self.tp_total + self.fn_total) if (self.tp_total + self.fn_total) > 0 else 0.0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        fpr = self.fp_total / (self.fp_total + self.tn_total) if (self.fp_total + self.tn_total) > 0 else 0.0
        fnr = self.fn_total / (self.fn_total + self.tp_total) if (self.fn_total + self.tp_total) > 0 else 0.0
        
        return {
            "total_flows": total,
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1_score": f1_score,
            "fpr": fpr,
            "fnr": fnr,
            "tp": self.tp_total,
            "tn": self.tn_total,
            "fp": self.fp_total,
            "fn": self.fn_total
        }
    
    def get_case_metrics(self, case_id: str) -> Optional[Dict]:
        """Get metrics for a specific case."""
        if case_id not in self.case_metrics:
            return None
        
        metrics = self.case_metrics[case_id]
        result = asdict(metrics)
        result["derived_metrics"] = metrics.calculate_metrics()
        return result
    
    def get_all_case_metrics(self) -> List[Dict]:
        """Get metrics for all cases."""
        results = []
        for case_id, metrics in self.case_metrics.items():
            result = asdict(metrics)
            result["derived_metrics"] = metrics.calculate_metrics()
            results.append(result)
        return results
    
    def export_flow_predictions(self, filepath: Optional[str] = None):
        """Export all flow predictions to JSON."""
        if filepath is None:
            filepath = str(self.output_dir / f"flow_predictions_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        
        data = [asdict(pred) for pred in self.flow_predictions]
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        
        print(f"Exported {len(data)} flow predictions to {filepath}")
        return filepath
    
    def export_case_metrics(self, filepath: Optional[str] = None):
        """Export case metrics to JSON."""
        if filepath is None:
            filepath = str(self.output_dir / f"case_metrics_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        
        data = self.get_all_case_metrics()
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        
        print(f"Exported metrics for {len(data)} cases to {filepath}")
        return filepath
    
    def export_confusion_matrix_csv(self, filepath: Optional[str] = None):
        """Export confusion matrix to CSV."""
        if filepath is None:
            filepath = str(self.output_dir / f"confusion_matrix_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
        
        with open(filepath, 'w', encoding='utf-8', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['', 'Predicted BENIGN', 'Predicted MALICIOUS'])
            writer.writerow(['Actual BENIGN', self.tn_total, self.fp_total])
            writer.writerow(['Actual MALICIOUS', self.fn_total, self.tp_total])
        
        print(f"Exported confusion matrix to {filepath}")
        return filepath
    
    def print_summary(self):
        """Print a summary of accuracy metrics."""
        metrics = self.get_overall_metrics()
        
        print("\n" + "="*60)
        print("ACCURACY MEASUREMENT SUMMARY")
        print("="*60)
        print(f"Total Flows Evaluated: {metrics['total_flows']}")
        print(f"\nConfusion Matrix:")
        print(f"  True Positives  (TP): {metrics['tp']:6d}")
        print(f"  True Negatives  (TN): {metrics['tn']:6d}")
        print(f"  False Positives (FP): {metrics['fp']:6d}")
        print(f"  False Negatives (FN): {metrics['fn']:6d}")
        print(f"\nPerformance Metrics:")
        print(f"  Accuracy:  {metrics['accuracy']:.4f} ({metrics['accuracy']*100:.2f}%)")
        print(f"  Precision: {metrics['precision']:.4f} ({metrics['precision']*100:.2f}%)")
        print(f"  Recall:    {metrics['recall']:.4f} ({metrics['recall']*100:.2f}%)")
        print(f"  F1 Score:  {metrics['f1_score']:.4f}")
        print(f"\nError Rates:")
        print(f"  False Positive Rate: {metrics['fpr']:.4f} ({metrics['fpr']*100:.2f}%)")
        print(f"  False Negative Rate: {metrics['fnr']:.4f} ({metrics['fnr']*100:.2f}%)")
        print(f"\nCase Statistics:")
        print(f"  Total Cases: {len(self.case_metrics)}")
        print("="*60 + "\n")
    
    def save_summary_report(self, filepath: Optional[str] = None):
        """Save a complete accuracy report."""
        if filepath is None:
            filepath = str(self.output_dir / f"accuracy_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        
        report = {
            "timestamp": datetime.now().isoformat(),
            "overall_metrics": self.get_overall_metrics(),
            "case_metrics": self.get_all_case_metrics(),
            "confusion_matrix": {
                "tp": self.tp_total,
                "tn": self.tn_total,
                "fp": self.fp_total,
                "fn": self.fn_total
            }
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
        
        print(f"Saved accuracy report to {filepath}")
        return filepath
