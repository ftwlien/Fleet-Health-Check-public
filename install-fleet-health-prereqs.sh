#!/usr/bin/env bash
set -euo pipefail

USER_NAME="${SUDO_USER:-$USER}"
SMARTCTL_PATH="$(command -v smartctl || true)"

if [[ -z "$USER_NAME" ]]; then
  echo "Could not determine target user."
  exit 1
fi

echo "== Fleet Health Check prerequisites =="
echo "Target user: $USER_NAME"

echo "-- apt update"
sudo apt update

echo "-- install smartmontools and build deps"
sudo apt install -y smartmontools build-essential libpci-dev curl

echo "-- install NVML development headers if available"
sudo apt install -y nvidia-cuda-toolkit || sudo apt install -y libnvidia-ml-dev || true

SMARTCTL_PATH="$(command -v smartctl || true)"
if [[ -z "$SMARTCTL_PATH" ]]; then
  echo "smartctl not found after install."
  exit 2
fi

echo "-- allow docker access for $USER_NAME"
sudo usermod -aG docker "$USER_NAME" || true

echo "-- allow passwordless smartctl for $USER_NAME"
SMART_SUDOERS="/etc/sudoers.d/smartctl-fleet-health-check"
echo "$USER_NAME ALL=(ALL) NOPASSWD: /usr/sbin/smartctl, /usr/bin/smartctl, $SMARTCTL_PATH" | sudo tee "$SMART_SUDOERS" >/dev/null
sudo chmod 440 "$SMART_SUDOERS"

echo "-- install ThomasBaruzier gputemps helper"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
curl -fsSL https://raw.githubusercontent.com/ThomasBaruzier/gddr6-core-junction-vram-temps/refs/heads/main/gputemps.c -o "$TMP_DIR/gputemps.c"
if cc -O3 "$TMP_DIR/gputemps.c" -o "$TMP_DIR/gputemps" -lnvidia-ml -lpci; then
  sudo install -m 0755 "$TMP_DIR/gputemps" /usr/local/bin/gputemps
  echo "$USER_NAME ALL=(ALL) NOPASSWD: /usr/local/bin/gputemps" | sudo tee /etc/sudoers.d/gputemps-fleet-health-check >/dev/null
  sudo chmod 440 /etc/sudoers.d/gputemps-fleet-health-check
else
  echo "WARN: gputemps build failed. Fleet Health Check will still work, but without junction/VRAM temps."
fi

echo "-- fix vast metrics launcher if present"
if [[ -f /var/lib/vastai_kaalia/latest/launch_metrics_pusher.sh ]]; then
  sudo chmod +x /var/lib/vastai_kaalia/latest/launch_metrics_pusher.sh
  sudo systemctl restart vast_metrics.service || true
fi

echo "-- clear stale failed units"
sudo systemctl reset-failed || true

echo

echo "== done =="
echo "Now disconnect and reconnect your SSH session so docker group membership applies."
echo

echo "Quick tests after reconnect:"
echo "  docker ps"
echo "  sudo -n smartctl -H /dev/nvme0n1"
echo "  sudo -n /usr/local/bin/gputemps --json --once   # if installed"
echo "  systemctl --failed"
