#!/usr/bin/env python3
"""
Ground Truth Labeler
Reads ground truth labels from traffic generation logs.
Used for measuring model accuracy by comparing predictions vs actual labels.
"""

import csv
from typing import Optional, Dict, Tuple
from datetime import datetime, timedelta
from pathlib import Path


class GroundTruthLabeler:
    """
    Labels flows based on ground truth from traffic generation.
    
    Primary strategy: Read labels from generate_traffic_with_labels.py output CSV
    Fallback: Time-window based matching if timestamps available
    """
    
    def __init__(
        self,
        labels_file: str = "/shared/flows/ground_truth_labels.csv",
        time_window_seconds: int = 5
    ):
        """
        Initialize the ground truth labeler.
        
        Args:
            labels_file: Path to CSV with ground truth labels from traffic generation
            time_window_seconds: Time window for matching flows to labels (default: 5s)
        """
        self.labels_file = labels_file
        self.time_window = timedelta(seconds=time_window_seconds)
        
        # Load labels from CSV
        self.labels = []  # List of label entries
        self.load_labels()
        
        print(f"Ground truth labeler initialized")
        print(f"Labels file: {labels_file}")
        print(f"Loaded {len(self.labels)} label entries")
    
    def load_labels(self):
        """Load ground truth labels from CSV file."""
        if not Path(self.labels_file).exists():
            print(f"WARNING: Labels file not found: {self.labels_file}")
            print("No ground truth labels available. All flows will be labeled as BENIGN by default.")
            return
        
        try:
            with open(self.labels_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    # Parse timestamp
                    timestamp_str = row.get('timestamp', '').strip()
                    try:
                        timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                    except Exception:
                        timestamp = None
                    
                    entry = {
                        'timestamp': timestamp,
                        'src_ip': row.get('src_ip', '').strip(),
                        'dst_ip': row.get('dst_ip', '').strip(),
                        'label': row.get('label', '').strip().upper(),
                        'activity_type': row.get('activity_type', '').strip(),
                        'description': row.get('description', '').strip()
                    }
                    
                    if entry['label'] in ['BENIGN', 'MALICIOUS']:
                        self.labels.append(entry)
        
        except Exception as e:
            print(f"ERROR: Failed to load labels from {self.labels_file}: {e}")
            self.labels = []
    
    def label_flow(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: Optional[int] = None,
        dst_port: Optional[int] = None,
        timestamp: Optional[datetime] = None,
        flow_id: Optional[str] = None
    ) -> Tuple[str, str]:
        """
        Determine ground truth label for a flow.
        
        Strategy:
        1. Match by (src_ip, dst_ip) within time window
        2. If no timestamp, match by (src_ip, dst_ip) for most recent label
        3. Default to BENIGN if no match
        
        Returns:
            Tuple of (label, reason) where:
            - label: "BENIGN" or "MALICIOUS"
            - reason: Explanation of why this label was assigned
        """
        if not self.labels:
            return "BENIGN", "no_labels_available"
        
        # Strategy 1: Match by IP and timestamp (if available)
        if timestamp:
            for label_entry in reversed(self.labels):  # Check most recent first
                if label_entry['timestamp'] is None:
                    continue
                
                # Check if IPs match
                if (label_entry['src_ip'] == src_ip and 
                    label_entry['dst_ip'] == dst_ip):
                    
                    # Check if within time window
                    time_diff = abs((timestamp - label_entry['timestamp']).total_seconds())
                    if time_diff <= self.time_window.total_seconds():
                        return (
                            label_entry['label'],
                            f"{label_entry['activity_type']}_time_match"
                        )
        
        # Strategy 2: Match by IP only (most recent)
        for label_entry in reversed(self.labels):
            if (label_entry['src_ip'] == src_ip and 
                label_entry['dst_ip'] == dst_ip):
                return (
                    label_entry['label'],
                    f"{label_entry['activity_type']}_ip_match"
                )
        
        # Strategy 3: Default to BENIGN
        return "BENIGN", "default_no_match"
    
    def reload_labels(self):
        """Reload labels from file (useful for long-running processes)."""
        self.labels = []
        self.load_labels()
    
    def get_statistics(self) -> Dict[str, int]:
        """Get statistics about loaded labels."""
        benign_count = sum(1 for l in self.labels if l['label'] == 'BENIGN')
        malicious_count = sum(1 for l in self.labels if l['label'] == 'MALICIOUS')
        
        return {
            'total': len(self.labels),
            'benign': benign_count,
            'malicious': malicious_count
        }
    
    def get_activity_types(self) -> Dict[str, int]:
        """Get count of each activity type."""
        activity_counts = {}
        for label_entry in self.labels:
            activity = label_entry['activity_type']
            activity_counts[activity] = activity_counts.get(activity, 0) + 1
        return activity_counts


# Convenience function for simple use cases
def label_flow_from_csv(
    src_ip: str,
    dst_ip: str,
    labels_file: str = "/shared/flows/ground_truth_labels.csv"
) -> str:
    """
    Simple labeling: Read from CSV generated by generate_traffic_with_labels.py
    
    Args:
        src_ip: Source IP address
        dst_ip: Destination IP address
        labels_file: Path to ground truth labels CSV
    
    Returns:
        "BENIGN" or "MALICIOUS"
    """
    labeler = GroundTruthLabeler(labels_file=labels_file)
    label, _ = labeler.label_flow(src_ip, dst_ip)
    return label
