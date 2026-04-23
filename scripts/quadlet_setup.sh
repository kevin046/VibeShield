#!/usr/bin/env bash
# Generate systemd quadlet units for Kraken services
# This enables native systemd management of Podman containers

set -euo pipefail

QUADLET_DIR="$HOME/.config/systemd/user"
KRAKEN_DIR="$(cd "$(dirname "$0")/.." && pwd)"

mkdir -p "$QUADLET_DIR"

echo "=== Generating systemd quadlet units ==="
echo ""

# Check if quadlet is available
if ! command -v podman &>/dev/null; then
    echo "ERROR: podman is not installed"
    exit 1
fi

# Generate orchestrator quadlet unit
cat > "$QUADLET_DIR/kraken-orchestrator.container" <<EOF
[Unit]
Description=Kraken Orchestrator (Layer 2)
After=network-online.target
Wants=network-online.target

[Container]
Image=clawmolt/kraken-base:latest
ContainerName=kraken-orchestrator
PublishPort=8080:8080
Network=kraken-internal
SecurityOpt=no-new-privileges
CapDrop=ALL
ReadOnly=true
Tmpfs=/tmp:size=100M,mode=1777
Environment=KRAKEN_MODE=PRODUCTION
Environment=KRAKEN_LOG_LEVEL=INFO
Volume=$KRAKEN_DIR/config:/app/config:ro
HealthCmd=python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')"

[Service]
Restart=always
TimeoutStartSec=30

[Install]
WantedBy=default.target
EOF

# Generate escrow quadlet unit
cat > "$QUADLET_DIR/kraken-escrow.container" <<EOF
[Unit]
Description=Kraken Escrow Engine (Layer 3)
After=kraken-orchestrator.service
Requires=kraken-orchestrator.service

[Container]
Image=clawmolt/escrow-vault:latest
ContainerName=kraken-escrow
Network=kraken-internal
SecurityOpt=no-new-privileges
CapDrop=ALL
ReadOnly=true
Tmpfs=/tmp:size=50M,mode=1777
Environment=KRAKEN_ESCROW_MODE=PRODUCTION

[Service]
Restart=always
TimeoutStartSec=30

[Install]
WantedBy=default.target
EOF

# Reload and enable
echo "Reloading systemd daemon..."
systemctl --user daemon-reload

echo "Enabling services..."
systemctl --user enable kraken-orchestrator.service
systemctl --user enable kraken-escrow.service

echo ""
echo "=== Quadlet setup complete ==="
echo ""
echo "To start:     systemctl --user start kraken-orchestrator"
echo "To stop:      systemctl --user stop kraken-orchestrator"
echo "To check:     systemctl --user status kraken-orchestrator"
echo "To see logs:  journalctl --user -u kraken-orchestrator -f"
