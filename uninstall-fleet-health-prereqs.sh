#!/usr/bin/env bash
set -euo pipefail

USER_NAME="${SUDO_USER:-$USER}"
REMOVE_PACKAGES="${REMOVE_PACKAGES:-0}"

echo "== Fleet Health Check uninstall =="
echo "Target user: $USER_NAME"
echo

echo "-- remove sudoers rules"
sudo rm -f /etc/sudoers.d/smartctl-fleet-health-check
sudo rm -f /etc/sudoers.d/gputemps-fleet-health-check

echo "-- remove gputemps binary if present"
sudo rm -f /usr/local/bin/gputemps

echo "-- remove docker group membership for $USER_NAME"
if getent group docker >/dev/null 2>&1; then
  sudo gpasswd -d "$USER_NAME" docker || true
fi

if [[ "$REMOVE_PACKAGES" == "1" ]]; then
  echo "-- remove packages installed for Fleet Health Check"
  sudo apt remove --purge -y smartmontools build-essential libpci-dev curl nvidia-cuda-toolkit libnvidia-ml-dev python3-pip btop || true
  sudo apt autoremove -y || true
else
  echo "-- keeping packages installed (default)"
  echo "   Set REMOVE_PACKAGES=1 if you really want package removal too."
fi

echo

echo "== done =="
echo "You can now delete the repo folder manually if you want:"
echo "  cd .. && rm -rf Fleet-Health-Check-public"
