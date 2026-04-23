#!/usr/bin/env bash
# Generate systemd quadlet units for VibeShield services
# This enables native systemd management of Podman containers

set -euo pipefail

QUADLET_DIR="$HOME/.config/systemd/user"
VIBESHIELD_DIR="$(cd "$(dirname "$0")/.." && pwd)"

mkdir -p "$QUADLET_DIR"

echo "=== Generating systemd quadlet units ==="
echo ""

# Check if quadlet is available
if ! command -v podman &>/dev/null; then
    echo "ERROR: podman is not installed"
    exit 1
fi

# Generate orchestrator quadlet unit
cat > "$QUADLET_DIR/vibeshield-orchestrator.container" <<EOF
[Unit]
Description=VibeShield Orchestrator (Layer 2)
After=network-online.target
Wants=network-online.target

[Container]
Image=vibeshield/base:latest
ContainerName=vibeshield-orchestrator
PublishPort=8080:8080
Network=vibeshield-internal
SecurityOpt=no-new-privileges
CapDrop=ALL
ReadOnly=true
Tmpfs=/tmp:size=100M,mode=1777
Environment=VIBESHIELD_MODE=PRODUCTION
Environment=VIBESHIELD_LOG_LEVEL=INFO
Volume=$VIBESHIELD_DIR/config:/app/config:ro
HealthCmd=python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')"

[Service]
Restart=always
TimeoutStartSec=30

[Install]
WantedBy=default.target
EOF

# Generate escrow quadlet unit
cat > "$QUADLET_DIR/vibeshield-escrow.container" <<EOF
[Unit]
Description=VibeShield Escrow Engine (Layer 3)
After=vibeshield-orchestrator.service
Requires=vibeshield-orchestrator.service

[Container]
Image=vibeshield/escrow:latest
ContainerName=vibeshield-escrow
Network=vibeshield-internal
SecurityOpt=no-new-privileges
CapDrop=ALL
ReadOnly=true
Tmpfs=/tmp:size=50M,mode=1777
Environment=VIBESHIELD_ESCROW_MODE=PRODUCTION

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
systemctl --user enable vibeshield-orchestrator.service
systemctl --user enable vibeshield-escrow.service

echo ""
echo "=== Quadlet setup complete ==="
echo ""
echo "To start:     systemctl --user start vibeshield-orchestrator"
echo "To stop:      systemctl --user stop vibeshield-orchestrator"
echo "To check:     systemctl --user status vibeshield-orchestrator"
echo "To see logs:  journalctl --user -u vibeshield-orchestrator -f"
