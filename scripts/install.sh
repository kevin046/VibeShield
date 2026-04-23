#!/usr/bin/env bash
# Quick install script for the VibeShield Security Framework
# Prerequisites: Podman 4.x+, Python 3.11+

set -euo pipefail

echo "=== VibeShield Security Framework Installer ==="
echo ""

# Check prerequisites
check_cmd() {
    if ! command -v "$1" &>/dev/null; then
        echo "ERROR: $1 is not installed. Please install it first."
        exit 1
    fi
    echo "  [OK] $1 ($(command -v "$1"))"
}

echo "Checking prerequisites..."
check_cmd podman
check_cmd python3
check_cmd git

# Check Podman version
PODMAN_VERSION=$(podman --version | grep -oP '\d+\.\d+' | head -1)
echo "  Podman version: $PODMAN_VERSION (>= 4.0 required)"

# Create virtual environment
echo ""
echo "Setting up Python environment..."
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip -q

# Install dependencies
echo "Installing Python dependencies..."
pip install -r requirements.txt -q

# Build the base image
echo ""
echo "Building VibeShield base image..."
podman build -t vibeshield/base:latest -f Containerfile .

echo ""
echo "=== Installation Complete ==="
echo ""
echo "Next steps:"
echo "  1. Start the stack:  podman-compose -f podman-compose.yaml up -d"
echo "  2. Run tests:        pytest tests/ -v"
echo "  3. Check health:     curl http://localhost:8080/health"
echo ""
echo "For systemd integration, run:"
echo "  ./scripts/quadlet_setup.sh"
