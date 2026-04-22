# path: infrastructure/setup_suricata.sh
#!/usr/bin/env bash
set -euo pipefail

echo "[*] Installing/configuring Suricata on moa..."

# Packages & dirs
docker exec moa bash -lc '
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq suricata tcpdump tshark net-tools iproute2 iputils-ping
  mkdir -p /logs/suricata /var/lib/suricata/rules
'

# Config
docker exec -i moa bash -lc 'cat > /etc/suricata/suricata.yaml' <<'YAML'
%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "[10.0.0.0/24]"
    EXTERNAL_NET: "!$HOME_NET"
    HTTP_SERVERS: "$HOME_NET"
    SQL_SERVERS: "$HOME_NET"
    DNS_SERVERS: "$HOME_NET"
    SMTP_SERVERS: "$HOME_NET"
    TELNET_SERVERS: "$HOME_NET"

  port-groups:
    HTTP_PORTS: "80,81,443,8000,8080,8888"
    SSH_PORTS: "22"
    ORACLE_PORTS: "1521"
    SHELLCODE_PORTS: "!$HTTP_PORTS"
    FILE_DATA_PORTS: "[$HTTP_PORTS,110,143]"

default-log-dir: /logs/suricata

af-packet:
  - interface: br-island
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
    ring-size: 20000
    treads: 4
    block-size: 65536
    buffer-size: 2048
    checksum-checks: auto

default-rule-path: /var/lib/suricata/rules
rule-files:
  - local.rules

outputs:
  - fast:
      enabled: yes
      filename: fast.log
      append: yes
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      community-id: true
      types: [ alert, flow, stats, http, dns, tls ]

detect-engine:
  profile: medium

app-layer:
  protocols:
    http:   { enabled: yes }
    tls:    { enabled: yes }
    dnp3:   { enabled: no }
    modbus: { enabled: no }

logging:
  default-log-level: info
  outputs:
    - file:
        enabled: yes
        level: info
        filename: /logs/suricata/suricata.log
YAML


# Local rules
docker exec -i moa bash -lc 'cat > /var/lib/suricata/rules/local.rules' <<'RULES'

# SYN-burst (portscan indicator)
alert tcp any any -> 10.0.0.0/24 any (flags:S; msg:"Possible Portscan"; threshold:type both, track by_src, count 20, seconds 5; sid:1000002; rev:1;)
RULES

# Validate config/rules
docker exec moa bash -lc 'suricata -T -c /etc/suricata/suricata.yaml -i br-island'

# Restart daemon
docker exec moa bash -lc '
  pkill -f "^suricata\b" || true
  suricata -c /etc/suricata/suricata.yaml -i br-island -D -l /logs/suricata -k none
'