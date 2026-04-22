#!/bin/bash
set -e

echo "=========================================="
echo "Tearing down lab environment"
echo "=========================================="

echo "[1/5] Stopping and removing compose services, volumes, and networks..."
docker compose down -v --remove-orphans

echo "[2/5] Removing island network if still present..."
docker network rm island 2>/dev/null || true

echo "[3/5] Removing leftover containers (host-network / manual)..."
docker rm -f moa cicflowmeter 2>/dev/null || true

echo "[4/5] Pruning unused Docker resources..."
docker system prune -f --volumes

echo "[5/5] Cleaning DFIR-IRIS artifacts..."
rm -rf iris-web

echo "=========================================="
echo "Lab teardown complete – network fully removed"
echo "=========================================="
