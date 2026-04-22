#!/usr/bin/env python3
"""
Generate Accuracy Report
Analyzes accuracy tracking data and generates comprehensive reports.

Usage:
    python generate_accuracy_report.py --input /shared/flows/accuracy --output report.md
"""

import argparse
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List
import sys


def load_accuracy_data(accuracy_dir: str) -> Dict:
    """Load the latest accuracy report from directory."""
    accuracy_path = Path(accuracy_dir)
    
    # Find most recent report
    report_files = sorted(accuracy_path.glob("accuracy_report_*.json"), reverse=True)
    
    if not report_files:
        print(f"ERROR: No accuracy reports found in {accuracy_dir}", file=sys.stderr)
        return None
    
    latest_report = report_files[0]
    print(f"Loading report: {latest_report}")
    
    with open(latest_report, 'r') as f:
        return json.load(f)


def generate_markdown_report(data: Dict, output_file: str):
    """Generate a markdown report from accuracy data."""
    
    overall = data.get("overall_metrics", {})
    cases = data.get("case_metrics", [])
    confusion = data.get("confusion_matrix", {})
    
    lines = []
    
    # Header
    lines.append("# Model Accuracy Report")
    lines.append("")
    lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"**Report Timestamp:** {data.get('timestamp', 'N/A')}")
    lines.append("")
    
    # Executive Summary
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(f"- **Total Flows Evaluated:** {overall.get('total_flows', 0):,}")
    lines.append(f"- **Overall Accuracy:** {overall.get('accuracy', 0)*100:.2f}%")
    lines.append(f"- **Precision:** {overall.get('precision', 0)*100:.2f}%")
    lines.append(f"- **Recall:** {overall.get('recall', 0)*100:.2f}%")
    lines.append(f"- **F1 Score:** {overall.get('f1_score', 0):.4f}")
    lines.append(f"- **Total Cases:** {len(cases)}")
    lines.append("")
    
    # Confusion Matrix
    lines.append("## Confusion Matrix")
    lines.append("")
    lines.append("```")
    lines.append("                    Predicted")
    lines.append("                BENIGN    MALICIOUS")
    lines.append("Actual  BENIGN   {:6d}      {:6d}".format(
        confusion.get('tn', 0), confusion.get('fp', 0)))
    lines.append("        MALICIOUS {:6d}      {:6d}".format(
        confusion.get('fn', 0), confusion.get('tp', 0)))
    lines.append("```")
    lines.append("")
    
    # Detailed Metrics
    lines.append("## Detailed Performance Metrics")
    lines.append("")
    lines.append("| Metric | Value | Description |")
    lines.append("|--------|-------|-------------|")
    lines.append(f"| **True Positives (TP)** | {confusion.get('tp', 0)} | Correctly identified malicious flows |")
    lines.append(f"| **True Negatives (TN)** | {confusion.get('tn', 0)} | Correctly identified benign flows |")
    lines.append(f"| **False Positives (FP)** | {confusion.get('fp', 0)} | Benign flows incorrectly flagged as malicious |")
    lines.append(f"| **False Negatives (FN)** | {confusion.get('fn', 0)} | Malicious flows missed by the model |")
    lines.append(f"| **False Positive Rate** | {overall.get('fpr', 0)*100:.2f}% | Of all benign flows, % incorrectly flagged |")
    lines.append(f"| **False Negative Rate** | {overall.get('fnr', 0)*100:.2f}% | Of all malicious flows, % missed |")
    lines.append("")
    
    # Per-Case Analysis
    lines.append("## Per-Case Analysis")
    lines.append("")
    
    if cases:
        lines.append("| Case ID | Src IP | Dst IP | Total Flows | TP | TN | FP | FN | Accuracy | Precision | Recall |")
        lines.append("|---------|--------|--------|-------------|----|----|----|----|----------|-----------|--------|")
        
        for case in cases:
            case_id = case.get('case_id', 'N/A')
            src_ip = case.get('src_ip', 'N/A')
            dst_ip = case.get('dst_ip', 'N/A')
            total = case.get('total_flows', 0)
            tp = case.get('tp_count', 0)
            tn = case.get('tn_count', 0)
            fp = case.get('fp_count', 0)
            fn = case.get('fn_count', 0)
            
            metrics = case.get('derived_metrics', {})
            acc = metrics.get('accuracy', 0) * 100
            prec = metrics.get('precision', 0) * 100
            rec = metrics.get('recall', 0) * 100
            
            lines.append(f"| {case_id} | {src_ip} | {dst_ip} | {total} | {tp} | {tn} | {fp} | {fn} | {acc:.1f}% | {prec:.1f}% | {rec:.1f}% |")
    else:
        lines.append("*No case-level data available.*")
    
    lines.append("")
    
    # Key Findings
    lines.append("## Key Findings")
    lines.append("")
    
    # Calculate some insights
    if overall.get('fp', 0) > overall.get('fn', 0):
        lines.append("- ⚠️ **High False Positive Rate**: The model is over-alerting, flagging benign traffic as malicious.")
        lines.append(f"  - Consider raising the anomaly threshold (currently at default)")
        lines.append(f"  - {confusion.get('fp', 0)} false alarms out of {confusion.get('tn', 0) + confusion.get('fp', 0)} benign flows")
    elif overall.get('fn', 0) > overall.get('fp', 0):
        lines.append("- ⚠️ **High False Negative Rate**: The model is missing malicious traffic.")
        lines.append(f"  - Consider lowering the anomaly threshold")
        lines.append(f"  - {confusion.get('fn', 0)} attacks missed out of {confusion.get('tp', 0) + confusion.get('fn', 0)} malicious flows")
    else:
        lines.append("- ✓ **Balanced Performance**: False positives and false negatives are relatively balanced.")
    
    lines.append("")
    
    if overall.get('accuracy', 0) > 0.95:
        lines.append("- ✓ **Excellent Accuracy**: Model performs very well with >95% accuracy.")
    elif overall.get('accuracy', 0) > 0.85:
        lines.append("- ✓ **Good Accuracy**: Model performs well with >85% accuracy.")
    elif overall.get('accuracy', 0) > 0.70:
        lines.append("- ⚠️ **Moderate Accuracy**: Model performance is acceptable but could be improved.")
    else:
        lines.append("- ❌ **Low Accuracy**: Model performance needs significant improvement.")
    
    lines.append("")
    
    # Recommendations
    lines.append("## Recommendations")
    lines.append("")
    
    if overall.get('fpr', 0) > 0.1:  # FPR > 10%
        lines.append("1. **Reduce False Positives:**")
        lines.append("   - Increase anomaly threshold")
        lines.append("   - Review feature importance - some features may be causing false alarms")
        lines.append("   - Consider additional training data with normal traffic patterns")
        lines.append("")
    
    if overall.get('fnr', 0) > 0.1:  # FNR > 10%
        lines.append("2. **Reduce False Negatives:**")
        lines.append("   - Decrease anomaly threshold")
        lines.append("   - Ensure training data includes diverse attack patterns")
        lines.append("   - Review missed attacks for common characteristics")
        lines.append("")
    
    if overall.get('precision', 0) < 0.8:
        lines.append("3. **Improve Precision:**")
        lines.append("   - Focus on reducing false positives")
        lines.append("   - Fine-tune model parameters")
        lines.append("   - Consider ensemble methods or additional features")
        lines.append("")
    
    if overall.get('recall', 0) < 0.8:
        lines.append("4. **Improve Recall:**")
        lines.append("   - Focus on reducing false negatives")
        lines.append("   - Ensure model sees diverse attack examples during training")
        lines.append("   - Consider lowering threshold or using more sensitive features")
        lines.append("")
    
    # Footer
    lines.append("---")
    lines.append("")
    lines.append("*This report was generated automatically by the accuracy measurement system.*")
    
    # Write report
    with open(output_file, 'w') as f:
        f.write('\n'.join(lines))
    
    print(f"\nMarkdown report saved to: {output_file}")


def generate_json_summary(data: Dict, output_file: str):
    """Generate a JSON summary for programmatic access."""
    
    overall = data.get("overall_metrics", {})
    confusion = data.get("confusion_matrix", {})
    
    summary = {
        "timestamp": datetime.now().isoformat(),
        "metrics": {
            "accuracy": overall.get('accuracy', 0),
            "precision": overall.get('precision', 0),
            "recall": overall.get('recall', 0),
            "f1_score": overall.get('f1_score', 0),
            "fpr": overall.get('fpr', 0),
            "fnr": overall.get('fnr', 0)
        },
        "confusion_matrix": {
            "tp": confusion.get('tp', 0),
            "tn": confusion.get('tn', 0),
            "fp": confusion.get('fp', 0),
            "fn": confusion.get('fn', 0)
        },
        "total_flows": overall.get('total_flows', 0),
        "total_cases": len(data.get("case_metrics", []))
    }
    
    with open(output_file, 'w') as f:
        json.dump(summary, f, indent=2)
    
    print(f"JSON summary saved to: {output_file}")


def main():
    parser = argparse.ArgumentParser(description="Generate accuracy report from tracking data")
    parser.add_argument("--input", default="/shared/flows/accuracy",
                        help="Directory containing accuracy tracking data")
    parser.add_argument("--output", default="accuracy_report.md",
                        help="Output markdown file")
    parser.add_argument("--json", default=None,
                        help="Optional JSON summary output")
    
    args = parser.parse_args()
    
    # Load data
    data = load_accuracy_data(args.input)
    if not data:
        sys.exit(1)
    
    # Generate markdown report
    generate_markdown_report(data, args.output)
    
    # Generate JSON summary if requested
    if args.json:
        generate_json_summary(data, args.json)
    
    print("\n✓ Report generation complete!")


if __name__ == "__main__":
    main()
