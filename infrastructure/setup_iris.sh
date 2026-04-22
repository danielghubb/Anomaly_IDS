#!/bin/bash

set -e

# Configuration
IRIS_VERSION="v2.4.24"  # Latest stable non-beta version from docs
IRIS_DIR="$(pwd)/iris-web"
IRIS_REPO="https://github.com/dfir-iris/iris-web.git"

echo "=========================================="
echo "DFIR-IRIS Setup"
echo "=========================================="

# Step 1: Clone or update iris-web repository
if [ ! -d "$IRIS_DIR" ]; then
    echo "Cloning iris-web repository..."
    git clone "$IRIS_REPO" "$IRIS_DIR"
# else
    echo "iris-web directory already exists, updating..."
    cd "$IRIS_DIR"
    git fetch --all --tags
    cd -
fi

# Step 2: Checkout the specified version
echo "Checking out version $IRIS_VERSION..."
cd "$IRIS_DIR"
git checkout "$IRIS_VERSION"
cd -

# Step 3: Ensure .env file exists
if [ ! -f "$IRIS_DIR/.env" ]; then
    echo "Creating .env file from .env.model..."
    cp "$IRIS_DIR/../.env.model" "$IRIS_DIR/.env"
    cp "$IRIS_DIR/../.env.model" "$IRIS_DIR/../.env"
    echo "NOTE: Using default .env configuration (suitable for testing only)"
    echo "      Edit $IRIS_DIR/.env for production settings"
else
    echo ".env file already exists, skipping..."
fi

echo ""
echo "=========================================="
echo "IRIS is now installed!"
echo "=========================================="