#!/bin/bash
# Master setup script for IDS lab environment

set -e

echo "=========================================="
echo "IDS Lab Environment Setup"
echo "=========================================="

# Check system dependencies
echo "Checking system dependencies..."

if ! command -v docker &> /dev/null; then
    echo "ERROR: Docker not installed"
    echo "Install from: https://docs.docker.com/get-docker/"
    exit 1
fi

if ! docker compose version &> /dev/null; then
    echo "ERROR: Docker Compose not available"
    exit 1
fi

if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python 3 not installed"
    exit 1
fi

echo "✓ Docker found: $(docker --version)"
echo "✓ Docker Compose found"
echo "✓ Python found: $(python3 --version)"
echo ""

# Setup Python virtual environment
echo "Setting up Python virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo "✓ Virtual environment created"
else
    echo "✓ Virtual environment exists"
fi

source venv/bin/activate

# Install Python dependencies
if [ -f "requirements.txt" ] && [ -s "requirements.txt" ]; then
    echo "Installing Python packages..."
    pip install --upgrade pip
    pip install -r requirements.txt
    echo "✓ Python packages installed"
else
    echo "⚠ requirements.txt empty or missing (will install as needed)"
fi

# Create necessary directories
echo ""
echo "Creating project directories..."
mkdir -p logs model shared flows

#unzip cicflowmeter
unzip infrastructure/cicflowmeter/vendor.zip -d infrastructure/cicflowmeter/

# Setup Docker infrastructure
echo ""
echo "Setting up Docker containers..."
cd infrastructure
chmod +x setup.sh teardown.sh
./setup.sh


echo "Setup complete!"
echo "=========================================="
echo "Login to IRIS:" 
echo "In Browser: https://localhost"
echo "Username:   admin"
echo "Password:   psswd"
echo "=========================================="