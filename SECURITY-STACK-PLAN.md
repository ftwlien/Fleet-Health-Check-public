# Fleet Security Stack Plan

## Goal
Add a dedicated security drift and alerting layer to the fleet without disturbing the normal fleet health views.

## Current CLI surfaces
- `python3 fleet_health_check.py --security`
- `python3 fleet_health_check.py --security --watch 5`
- `python3 fleet_health_check.py --security-baseline save`
- `python3 fleet_health_check.py --security-telegram-watch 60`

## Current data collected
- UID 0 users
- sudo / wheel / docker group membership
- authorized_keys inventory/count
- listening ports inventory/count
- loaded kernel modules inventory/count
- systemd service/timer inventory/count
- cron file inventory/count
- hashes / readability state for:
  - `/etc/passwd`
  - `/etc/shadow`
  - `/etc/group`
  - `/etc/sudoers`
  - `/etc/ssh/sshd_config`
  - `/etc/sudoers.d/*`

## Baseline model
Save a known-good baseline after reviewing the fleet:

```bash
python3 fleet_health_check.py --security-baseline save
```

After baseline save, `--security` compares live state against that baseline and raises drift flags.

## Severity model
### BAD
- UID0 drift
- sudo drift
- wheel drift
- passwd changed
- shadow changed (if readable baseline exists)
- sudoers changed
- sshd_config changed
- authorized_keys drift
- sudoers.d drift
- port drift
- kernel module drift

### WATCH
- docker group drift
- systemd drift
- cron drift

## Recommended software to add

### 1. auditd
Purpose: fast event-level detection for sensitive files and privileged activity.

Use for:
- `/etc/passwd`
- `/etc/shadow`
- `/etc/sudoers`
- `/etc/sudoers.d/`
- SSH authorized key paths
- module load activity
- privileged command execution

### 2. AIDE
Purpose: integrity baseline and tamper detection across critical paths.

Use for:
- system config drift
- file tampering
- persistence paths
- optional binary integrity checks

### 3. osquery
Purpose: richer host telemetry and queryable state.

Use for:
- users/groups
- listening ports
- kernel modules
- packages
- services
- scheduled tasks
- persistence checks

## Recommended rollout order
1. Get `--security` baseline saved and reviewed
2. Add Telegram alerting for BAD/WATCH transitions
3. Install `auditd` on all rigs
4. Add `auditd` watch rules for critical auth / privilege / persistence files
5. Install `AIDE` and initialize reviewed baselines
6. Optionally add `osquery` for richer visibility later

## Notes on permissions
Non-root collection will not reliably read protected files like `/etc/shadow`.
Current collector handles this gracefully with `permission-denied` markers instead of crashing.
If deeper security coverage is needed later, add controlled sudo read-only helpers for the security collector.
