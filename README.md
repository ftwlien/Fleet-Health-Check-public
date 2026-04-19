# Fleet Health Check

Read-only SSH-based fleet health check for GPU servers, Docker hosts, and Vast rigs.

## Quick summary

This is a read-only SSH-based rig health script for checking GPU / Vast / Docker machines fast from one place.

What it shows:
- rig reachability
- Docker / Vast status
- idle vs rented hints
- GPU temps / usage / power
- PCIe width
- NVMe health
- failed services
- reboot / uptime hints

What the one-time installer does:
- installs `smartmontools`
- adds your user to the `docker` group
- enables passwordless `smartctl`
- tries to install/build `gputemps` for junction / VRAM temps
- fixes some common fresh-rig permission issues

What it does **not** do:
- does not control Vast
- does not change pricing
- does not create renters / instances
- does not need a Vast API key for normal health checks

Important:
- the computer running this script must have SSH access to every machine it wants information from
- if SSH does not work, Fleet Health Check will fail too

It gives you a fast snapshot of:
- SSH reachability
- Docker / Vast service state
- rented vs idle hints
- GPU temps / util / power
- PCIe width
- NVMe health
- failed services
- reboot-needed / recent reboot hints

## Quick start

### 1. One-time install on each rig

```bash
git clone https://github.com/ftwlien/Fleet-Health-Check-public.git && cd Fleet-Health-Check-public && bash install-fleet-health-prereqs.sh
```

That installs the required rig-side bits like:
- `smartmontools`
- Docker group access
- `gputemps` helper (if it can build on that machine)

After it finishes, reconnect your SSH session on that rig.

### 3. Edit your rig list

Open:

```bash
nano fleet_health_check.py
```

Replace the example `RIGS` block with your own SSH targets:

```python
RIGS = [
    ("rig1-hostname", "user@192.168.1.10"),
    ("rig2-hostname", "user@192.168.1.11"),
]
```

Format:

```python
("label-you-want-to-see", "ssh_user@ip_or_hostname")
```

### 4. Test SSH manually first

```bash
ssh user@192.168.1.10 hostname
```

If SSH does not work, the script will fail too.

## Run

Default view:

```bash
python3 fleet_health_check.py
```

Vertical view:

```bash
python3 fleet_health_check.py --vertical
```

Live watch mode:

```bash
python3 fleet_health_check.py --watch 5
```

Vertical watch mode:

```bash
python3 fleet_health_check.py --vertical --watch 5
```

Flags-only view:

```bash
python3 fleet_health_check.py --flags
```

Flags watch mode:

```bash
python3 fleet_health_check.py --flags --watch 5
```

## Notes

- The script is read-only.
- It uses SSH for checks.
- `gputemps` is optional. If it cannot build/work on a machine, the script still works with normal GPU core temp from `nvidia-smi`.
- Watch mode auto-fits better on narrower terminals.

## Uninstall / cleanup

Basic cleanup:

```bash
bash uninstall-fleet-health-prereqs.sh
```

If you also want to remove packages that were installed for it:

```bash
REMOVE_PACKAGES=1 bash uninstall-fleet-health-prereqs.sh
```
