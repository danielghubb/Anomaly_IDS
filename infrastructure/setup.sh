#!/bin/bash

set -e

echo "install up DFIR-IRIS"
./setup_iris.sh


echo "Stopping old containers..."
docker compose -f docker-compose.yml down --remove-orphans

echo "Rebuilding cicflowmeter image..."
docker compose -f docker-compose.yml build --no-cache cicflowmeter

echo "Starting containers..."
docker compose -f docker-compose.yml up -d --force-recreate

#echo "Starting containers..."
#docker compose up -d

echo "Waiting for containers..."
sleep 5

echo "Setting up dodo (web-server)..."
docker exec dodo bash -c "apt update -qq && DEBIAN_FRONTEND=noninteractive apt install -y openssh-server apache2 netcat-openbsd iproute2 iputils-ping && service ssh start && service apache2 start"
echo "Setting up takahe (db-server)..."
docker exec takahe bash -c "apt update -qq && DEBIAN_FRONTEND=noninteractive apt install -y openssh-server mysql-server iproute2 iputils-ping && service ssh start"
echo "Setting up kiwi (app-server)..."
docker exec kiwi bash -c "apt update -qq && DEBIAN_FRONTEND=noninteractive apt install -y openssh-server nginx vsftpd iproute2 iputils-ping && service ssh start && service nginx start"
echo "Setting up cassowary (attacker)..."
docker exec cassowary bash -c "apt update -qq && DEBIAN_FRONTEND=noninteractive apt install -y nmap hping3 masscan netcat-traditional iproute2 iputils-ping"
echo "Setting up moa (monitor)..."
docker exec moa bash -c "apt update -qq && DEBIAN_FRONTEND=noninteractive apt install -y tcpdump suricata python3-pip tshark net-tools iproute2 iputils-ping"
echo "Installing Python dependencies in moa..."
docker exec -i moa pip3 install -r /dev/stdin < ../requirements.txt

# Wait a short while for containers to be ready
sleep 4

CONTAINERS=(cassowary dodo takahe kiwi moa)

echo "==> Ensuring dependencies are installed in containers "
for c in "${CONTAINERS[@]}"; do
  echo -n "  - ${c} : "

  # Ensure shared mount exists
  docker exec "${c}" sh -c 'mkdir -p /shared >/dev/null 2>&1 || true'

  # Install tcpdump if missing (Debian/Ubuntu/Kali based images)
  docker exec "${c}" sh -c '
    if ! command -v tcpdump >/dev/null 2>&1; then
      echo "installing tcpdump"
      export DEBIAN_FRONTEND=noninteractive
      apt-get update >/dev/null && apt-get install -y tcpdump >/dev/null || true
    else
      echo "tcpdump ok"
    fi
  ' || echo "warning: could not ensure tcpdump in ${c}"

  # Install Python requirements if a requirements.txt was mounted to /shared
  docker exec "${c}" sh -c '
    if [ -f /shared/requirements.txt ]; then
      echo "found /shared/requirements.txt, running pip install"
      pip install -r /shared/requirements.txt >/dev/null 2>&1 || true
    else
      echo "no /shared/requirements.txt"
    fi
  ' || echo "warning: pip install step failed in ${c}"

done

# Install Python requirements by piping the file directly
  if docker exec moa command -v pip3 >/dev/null 2>&1; then
    echo "installing Python requirements"
    docker exec -i moa pip3 install -r /dev/stdin < ../requirements.txt >/dev/null 2>&1 || echo "warning: pip install failed in ${c}"
  else
    echo "no pip3 available"
  fi


echo "==> Verification (tcpdump paths):"
for c in "${CONTAINERS[@]}"; do
  docker exec "${c}" sh -c 'printf "%s: " "$(hostname)"; command -v tcpdump || echo "MISSING"'
done

echo "Installing & configuring Suricata via setup_suricata.sh..."
chmod +x ./setup_suricata.sh 2>/dev/null || true
./setup_suricata.sh

echo "Starting Iris Pipeline..."
docker exec moa bash -c "python3 /shared/suricata-iris-pipeline.py &"

#rewrite libraries for cicflowmeter
docker compose exec cicflowmeter sh -lc '
  ln -sf /usr/lib/x86_64-linux-gnu/libpcap.so.0.8 /usr/lib/x86_64-linux-gnu/libpcap.so
  ldd /opt/cicflowmeter/jnetpcap/libjnetpcap.so | grep -q libpcap || echo "libpcap NICHT gefunden"
'


#start live evaluation of network traffic
docker exec moa bash -lc "
  nohup python3 /shared/flows/eval_flows_live.py \
    --csv /flows/live_flow_features.csv \
    --model /model/RandomForestModel.pkl \
    --case-batch-size 20 \
    --case-inactivity 120 \
    --threshold 0.51 \
    --poll 0.25 \
    --state /shared/eval_state.json \
    > /logs/eval_flows_live.log 2>&1 &
"





CONTAINERS=(cassowary dodo takahe kiwi iris iris_app)

echo ""
echo "=========================================="
echo "Setup sanity check: "
echo "should be: "
echo "=========================================="
echo "Network: 10.0.0.0/24 (island)"
echo ""
echo "Cassowary:   10.0.0.10  (attacker)"
echo "Dodo:        10.0.0.101 (generic host)"
echo "Takahe:      10.0.0.102 (generic host)"
echo "Kiwi:        10.0.0.103 (generic host)"
echo ""
echo "Iris:        10.0.0.6   (DFIR-IRIS nginx)"
echo "Iris_app:    10.0.0.7   (DFIR-IRIS app)"
echo ""
echo "Moa:         host-net   (monitor / packet inspection)"
echo "CICFlowMeter host-net   (flow feature extraction)"
echo ""
echo "=========================================="
echo "is: "

for c in "${CONTAINERS[@]}"; do
    hostname=$(docker exec "$c" sh -c 'hostname' 2>/dev/null || echo "$c")
    ip=$(docker inspect -f '{{$sep := ""}}{{range .NetworkSettings.Networks}}{{$sep}}{{.IPAddress}}{{$sep = " | "}}{{end}}' "$c" 2>/dev/null || echo "N/A")

    printf "  - %-9s: %-15s (%s)\n" "$c" "$ip" "$hostname"
done


echo "=========================================="
echo "Access Container:"
echo "  docker exec -it <container> bash"
echo ""
echo "Test Portscan:"
echo "  docker exec cassowary nmap -sS 10.0.0.101-103"
echo ""
echo "Network info:"
echo "  docker exec <container> bash /shared/network_info.sh"
echo "=========================================="