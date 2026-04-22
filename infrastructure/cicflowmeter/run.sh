#!/bin/bash
set -euo pipefail


# Configuration (via env vars)

IFACE="${CIC_IFACE:-br-island}"
PCAP_IN="/flows/pcap"

OUT_DIR="${OUT_DIR:-/flows/cic_out}"
FINAL_CSV="${FINAL_CSV:-/flows/live_flow_features.csv}"

ROTATE_SEC="${ROTATE_SEC:-5}"     # tcpdump rotates PCAP every N seconds
SLEEP_SEC="${SLEEP_SEC:-2}"       # polling interval

# Minimum age a PCAP must have before processing (avoid half-written files). 0.2 min = 12 seconds. Adjust via env if you want.
MIN_AGE_MIN="${MIN_AGE_MIN:-0.2}"


# Prepare directories / perms
mkdir -p "$PCAP_IN"
mkdir -p "$OUT_DIR"
chmod -R a+rwx /flows || true


# Resolve jnetpcap native libs
JNP_SO_FILE="$(find /opt/cicflowmeter/jnetpcap -maxdepth 3 -type f -name 'libjnetpcap*.so*' -print -quit || true)"
if [ -z "$JNP_SO_FILE" ]; then
  echo "[cicflowmeter] ERROR: libjnetpcap*.so not found under /opt/cicflowmeter/jnetpcap"
  find /opt/cicflowmeter/jnetpcap -maxdepth 3 -type f -name '*.so*' -print || true
  exit 1
fi
JNP_SO_DIR="$(dirname "$JNP_SO_FILE")"

export LD_LIBRARY_PATH="${JNP_SO_DIR}:${LD_LIBRARY_PATH:-}"
echo "[cicflowmeter] jnetpcap so dir: $JNP_SO_DIR"
echo "[cicflowmeter] LD_LIBRARY_PATH=$LD_LIBRARY_PATH"

# Ensure libpcap.so exists (jnetpcap often expects the unversioned name)
if [ ! -e /usr/lib/x86_64-linux-gnu/libpcap.so ] && [ -e /usr/lib/x86_64-linux-gnu/libpcap.so.0.8 ]; then
  ln -sf /usr/lib/x86_64-linux-gnu/libpcap.so.0.8 /usr/lib/x86_64-linux-gnu/libpcap.so || true
fi


# Start tcpdump capture
tcpdump -Z root -i "$IFACE" -n -U -G "$ROTATE_SEC" -w "$PCAP_IN/%Y%m%d%H%M%S.pcap" &
TCPDUMP_PID=$!

cleanup() {
  kill "$TCPDUMP_PID" 2>/dev/null || true
}
trap cleanup EXIT


# Main processing loop
while true; do
  find "$PCAP_IN" -name "*.pcap" -type f -mmin +"$MIN_AGE_MIN" 2>/dev/null | while read -r pcap; do
    [ -e "$pcap" ] || { sleep "$SLEEP_SEC"; continue; }

    base="$(basename "$pcap")"
    echo "[cicflowmeter] processing $base"

    if java \
      -Djava.library.path="$JNP_SO_DIR" \
      -cp "/opt/cicflowmeter/jnetpcap/jnetpcap.jar:/opt/cicflowmeter/lib/*" \
      cic.cs.unb.ca.ifm.Cmd "$pcap" "$OUT_DIR"
    then
      # Merge any CSVs produced into the final live CSV (skip headers on append)
      for csv in "$OUT_DIR"/*.csv; do
        [ -e "$csv" ] || continue
        if [ ! -f "$FINAL_CSV" ]; then
          cp "$csv" "$FINAL_CSV"
        else
          tail -n +2 "$csv" >> "$FINAL_CSV" || true
        fi
        rm -f "$csv"
      done

      # IMPORTANT: delete processed PCAP to avoid duplicate processing
      rm -f "$pcap"
    else
      echo "[cicflowmeter] ERROR: CICFlowMeter failed for $base (leaving PCAP for retry)"
    fi
  done

  sleep "$SLEEP_SEC"
done
