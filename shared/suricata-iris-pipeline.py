#!/usr/bin/env python3
"""
Suricata to IRIS Pipeline
Monitors eve.json for new events and sends alerts to IRIS
Runs inside the moa container
"""

import json
import time
import os
import sys
import logging
from pathlib import Path
from datetime import datetime
import urllib3
from dfir_iris_client.session import ClientSession
from dfir_iris_client.alert import Alert

# Suppress SSL warnings for self-signed certificates in lab environment
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging
LOG_FILE = "/logs/suricata-iris-pipeline.log"
LOG_FORMAT = '%(asctime)s [%(levelname)s] %(message)s'
LOG_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'

# Create logs directory if it doesn't exist
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

# Configure logger with both file and console handlers
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# File handler - detailed logging to file
file_handler = logging.FileHandler(LOG_FILE)
file_handler.setLevel(logging.INFO)
file_formatter = logging.Formatter(LOG_FORMAT, datefmt=LOG_DATE_FORMAT)
file_handler.setFormatter(file_formatter)

# Console handler - also log to stdout for monitoring
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO)
console_formatter = logging.Formatter(LOG_FORMAT, datefmt=LOG_DATE_FORMAT)
console_handler.setFormatter(console_formatter)

# Add handlers to logger
logger.addHandler(file_handler)
logger.addHandler(console_handler)

# Eve.json path inside moa container
EVE_JSON_PATH = "/logs/suricata/eve.json"
CHECK_INTERVAL = 1  # seconds

# IRIS Configuration (inside moa container with host network)
IRIS_URL = "https://10.0.0.6"  # nginx container on island network
IRIS_API_KEY = "B8BA5D730210B50F41C06941582D7965D57319D5685440587F98DFDC45A01594"

iris_session = None


def initialize_iris_session():
    """
    Initialize IRIS client for sending alerts.
    Returns: iris_client
    """
    global iris_session

    logger.info("Initializing IRIS session...")
    logger.info(f"URL: {IRIS_URL}")

    try:
        iris_session = ClientSession(
            apikey=IRIS_API_KEY,
            host=IRIS_URL,
            ssl_verify=False
        )

        logger.info("IRIS session initialized successfully")
        logger.info(f"Alerts will be sent to IRIS Alerts module")
        logger.info(f"Access alerts at: {IRIS_URL}/alerts")

        return iris_session

    except Exception as e:
        logger.error(f"Failed to initialize IRIS session: {e}")
        logger.exception("Exception details:")
        return None


def yield_file(filepath):
    """
    Generator that yields new lines appended to a file.
    Similar to 'tail -F' behavior.
    """
    while not os.path.exists(filepath):
        logger.info(f"Waiting for {filepath} to be created...")
        time.sleep(CHECK_INTERVAL)

    logger.info(f"Monitoring {filepath} for new events...")

    with open(filepath, 'r') as file:
        file.seek(0, os.SEEK_END)

        while True:
            line = file.readline()

            if line:
                yield line
            else:
                time.sleep(CHECK_INTERVAL)


def send_alert_to_iris(event):
    """
    Send a Suricata alert to IRIS Alerts module
    """
    global iris_session

    if not iris_session:
        logger.error("No IRIS session available")
        return False

    try:
        # Extract alert details
        timestamp_str = event.get('timestamp', datetime.now().isoformat())
        src_ip = event.get('src_ip', 'unknown')
        dest_ip = event.get('dest_ip', 'unknown')
        src_port = event.get('src_port', '')
        dest_port = event.get('dest_port', '')
        proto = event.get('proto', 'unknown')

        alert_info = event.get('alert', {})
        signature = alert_info.get('signature', 'Unknown alert')
        signature_id = alert_info.get('signature_id', 0)
        severity = alert_info.get('severity', 3)  # Default to low
        category = alert_info.get('category', 'Unknown')

        # Create alert title and description
        alert_title = f"Suricata: {signature}"
        alert_description = f"""Detected network activity matching signature: {signature}

**Network Flow:**
- Source: {src_ip}:{src_port}
- Destination: {dest_ip}:{dest_port}
- Protocol: {proto}

**Alert Details:**
- Signature ID: {signature_id}
- Category: {category}
- Severity: {severity}
- Timestamp: {timestamp_str}
"""

        # Prepare alert data for IRIS
        alert_data = {
            "alert_title": alert_title,
            "alert_description": alert_description,
            "alert_source": "Suricata IDS",
            "alert_severity_id": min(severity, 3),  # IRIS severity: 1-3 (Informational, Low, Medium, High)
            "alert_status_id": 2,  # New
            "alert_source_content": {
                "src_ip": src_ip,
                "src_port": src_port,
                "dest_ip": dest_ip,
                "dest_port": dest_port,
                "proto": proto,
                "signature": signature,
                "signature_id": signature_id,
                "category": category,
                "severity": severity,
                "timestamp": timestamp_str,
                "raw_event": event
            },
            "alert_tags": f"suricata,ids,severity-{severity}",
            "alert_customer_id": 1  # Default customer
        }

        # Send to IRIS Alerts
        alert_client = Alert(session=iris_session)
        result = alert_client.add_alert(alert_data=alert_data)

        if result.is_success():
            alert_id = result.get_data().get('alert_id')
            logger.info(f"Alert ID: {alert_id}")
            return True
        else:
            logger.error(f"Failed to send alert to IRIS: {result.get_msg()}")
            return False

    except Exception as e:
        logger.error(f"Error sending alert to IRIS: {e}")
        logger.exception("Exception details:")
        return False


def process_event(event_line):
    """
    Process a single JSON event from eve.json
    """
    try:
        event = json.loads(event_line)
        event_type = event.get('event_type', 'unknown')

        # Only process alerts for now
        if event_type == 'alert':
            timestamp = event.get('timestamp', 'N/A')
            src_ip = event.get('src_ip', 'N/A')
            dest_ip = event.get('dest_ip', 'N/A')
            signature = event.get('alert', {}).get('signature', 'N/A')
            severity = event.get('alert', {}).get('severity', 'N/A')

            logger.warning(f"ALERT: {timestamp} | {src_ip} -> {dest_ip} | {signature} (severity: {severity})")

            # Send to IRIS Alerts
            if send_alert_to_iris(event):
                logger.info(f"Successfully sent to IRIS Alerts")
            else:
                logger.error(f"Failed to send to IRIS Alerts")


    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse JSON: {e}")
        logger.debug(f"Line: {event_line[:100]}...")
    except Exception as e:
        logger.error(f"Error processing event: {e}")


def main():
    """
    Main loop: monitor eve.json and process new events
    """
    logger.info("=" * 60)
    logger.info("Suricata to IRIS Pipeline")
    logger.info("=" * 60)
    logger.info(f"Log file: {LOG_FILE}")
    logger.info(f"Eve.json path: {EVE_JSON_PATH}")
    logger.info(f"IRIS endpoint: {IRIS_URL}")
    logger.info(f"Check interval: {CHECK_INTERVAL}s")
    logger.info("Press Ctrl+C to stop")
    logger.info("=" * 60)

    # Initialize IRIS session
    session = initialize_iris_session()

    if not session:
        logger.error("Failed to initialize IRIS session. Exiting.")
        logger.error("Make sure IRIS is running and accessible.")
        sys.exit(1)

    logger.info("=" * 60)
    logger.info("Starting event monitoring...")
    logger.info("=" * 60)

    try:
        for line in yield_file(EVE_JSON_PATH):
            line = line.strip()
            if line:
                process_event(line)

    except KeyboardInterrupt:
        logger.info("\nStopping pipeline...")
        logger.info(f"Alerts available at: {IRIS_URL}/alerts")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        logger.exception("Exception details:")
        sys.exit(1)


if __name__ == "__main__":
    main()
