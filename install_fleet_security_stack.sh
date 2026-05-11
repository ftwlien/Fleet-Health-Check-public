#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "Run as root" >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

echo "== Fleet Health Check security stack =="
echo "-- apt update"
apt-get update

echo "-- install auditd + aide"
apt-get install -y auditd aide

echo "-- install audit rules"
install -d -m 0755 /etc/audit/rules.d
cat >/etc/audit/rules.d/fleet-security.rules <<'EOF'
-w /etc/passwd -p wa -k fleet_identity
-w /etc/group -p wa -k fleet_identity
-w /etc/shadow -p wa -k fleet_shadow
-w /etc/sudoers -p wa -k fleet_priv_esc
-w /etc/sudoers.d/ -p wa -k fleet_priv_esc
-w /etc/ssh/sshd_config -p wa -k fleet_ssh
-w /root/.ssh/authorized_keys -p wa -k fleet_ssh_keys
-w /home/ -p wa -k fleet_home_ssh_keys
-w /etc/systemd/system/ -p wa -k fleet_systemd
-w /etc/cron.d/ -p wa -k fleet_cron
-w /etc/crontab -p wa -k fleet_cron
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k fleet_kmod
EOF

echo "-- enable auditd"
augenrules --load || true
systemctl enable --now auditd

echo "-- write focused AIDE config"
cat >/etc/aide/aide.conf <<'EOF'
@@define DBDIR /var/lib/aide

database_in=file:@@{DBDIR}/aide.db
database_out=file:@@{DBDIR}/aide.db.new
database_new=file:@@{DBDIR}/aide.db.new
gzip_dbout=no

Checksums = sha256
OwnerModeNLink = p+u+g+s+m+c+n
Normal = OwnerModeNLink+Checksums
Dir = OwnerModeNLink

/etc Normal
/etc/passwd Normal
/etc/group Normal
/etc/shadow Normal
/etc/sudoers Normal
/etc/sudoers.d Dir
/etc/sudoers.d/.* Normal
/etc/ssh Dir
/etc/ssh/sshd_config Normal
/root/.ssh Dir
/root/.ssh/authorized_keys Normal
/etc/systemd/system Dir
/etc/systemd/system/.* Normal
/etc/cron.d Dir
/etc/cron.d/.* Normal
/etc/crontab Normal

!/var/lib/docker
!/var/lib/containers
!/var/lib/vastai_kaalia
!/var/cache
!/var/tmp
!/tmp
!/run
!/proc
!/sys
!/dev
!/home
!/mnt
!/media
!/snap
EOF

echo "-- initialize AIDE database if missing"
rm -f /var/lib/aide/aide.db.new /var/lib/aide/aide.db.new.gz
if [[ ! -f /var/lib/aide/aide.db && ! -f /var/lib/aide/aide.db.gz ]]; then
  if command -v aide >/dev/null 2>&1; then
    aide --config=/etc/aide/aide.conf --init || true
  elif command -v aide.wrapper >/dev/null 2>&1; then
    aide.wrapper --init || true
  fi
fi
if [[ -f /var/lib/aide/aide.db.new ]]; then
  cp -f /var/lib/aide/aide.db.new /var/lib/aide/aide.db
fi
if [[ -f /var/lib/aide/aide.db.new.gz ]]; then
  cp -f /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
fi

echo "-- install helper command"
cat >/usr/local/bin/fleet-security-check <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

echo '=== auditd status ==='
systemctl is-active auditd || true

echo
echo '=== loaded audit rules ==='
auditctl -l || true

echo
echo '=== recent audit hits ==='
ausearch -k fleet_identity -k fleet_shadow -k fleet_priv_esc -k fleet_ssh -k fleet_ssh_keys -k fleet_systemd -k fleet_cron -k fleet_kmod 2>/dev/null | tail -n 80 || true

echo
echo '=== AIDE database ==='
ls -lh /var/lib/aide/aide.db* 2>/dev/null || true

echo
echo '=== AIDE check ==='
if command -v aide.wrapper >/dev/null 2>&1; then
  aide.wrapper --check || true
else
  aide --config=/etc/aide/aide.conf --check || true
fi
EOF
chmod +x /usr/local/bin/fleet-security-check

echo
echo "== done =="
echo "Quick tests:"
echo "  systemctl is-active auditd"
echo "  sudo /usr/local/bin/fleet-security-check"
echo "  ls -lh /var/lib/aide/aide.db*"
