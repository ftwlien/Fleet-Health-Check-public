# Fleet Health Check

Simple read-only Python script for checking the health of a fleet of SSH-reachable machines.

It is meant to give you a fast operational snapshot across all rigs in one view, so you can quickly spot things like:

- a rig that is down or unreachable
- `vastai` or Docker not running
- a box that is rented but barely using the GPUs
- overheating GPUs
- low disk space
- PCIe lane issues
- pending reboot state
- NVMe / SSD health problems

## What it checks

- SSH connectivity
- hostname
- uptime
- service status (`vastai`, `docker`)
- running container count
- GPU temperatures
- GPU utilization
- GPU power draw
- NVIDIA driver version
- RAM usage
- PCIe link width
- reboot-required status
- NVMe SMART health
- failed systemd service count
- load average
- boot time / recent reboot clue
- NTP sync state
- basic network sanity (DNS + ping)
- recent OOM hint
- recent meaningful NIC/network event hint
- GPU memory usage
- lightweight container/workload hint
- disk usage
- simple health flags (`GOOD`, `WATCH`, `BAD`)

## Requirements

- Python 3
- SSH client
- key-based SSH access to all target machines
- `smartmontools` on target rigs if you want NVMe health reported
- a working `gputemps` command on target rigs if you want junction / VRAM temps too

## Setup

### One-time install on each rig

If you want the quickest path, run this once on each rig after cloning this repo:

```bash
git clone https://github.com/ftwlien/Fleet-Health-Check-public.git
cd Fleet-Health-Check-public
bash install-fleet-health-prereqs.sh
```

If you are already inside the repo folder, this shorter version also works:

```bash
bash install-fleet-health-prereqs.sh
```

### Uninstall / cleanup

If you want to remove the Fleet Health Check sudoers rules and helper binary later:

```bash
bash uninstall-fleet-health-prereqs.sh
```

By default, that keeps packages installed and only removes the Fleet Health Check specific changes.

If you really want to also remove packages that were installed for it:

```bash
REMOVE_PACKAGES=1 bash uninstall-fleet-health-prereqs.sh
```

This works on any network. It does **not** depend on any specific local LAN setup.

What it does:

- installs `smartmontools`
- installs basic build dependencies for the GPU temp helper
- adds your current user to the `docker` group
- grants passwordless `smartctl` for the current user
- downloads and builds ThomasBaruzier's `gputemps` tool for Linux junction / VRAM temps
- installs `gputemps` to `/usr/local/bin/gputemps`
- grants passwordless `gputemps` for the current user
- fixes Vast metrics launcher permissions if needed
- clears stale failed-unit noise

What access it needs:

- a normal shell on the target rig
- the ability to run `sudo`
- Internet access for `apt update` / package install and fetching `gputemps.c`

What it does **not** do:

- it does not configure your router
- it does not open firewall ports
- it does not create SSH keys for you automatically
- it does not edit your `RIGS` list for you
- it does not expose anything publicly
- it does not change GRUB / Secure Boot settings for `gputemps`

After it finishes:

1. disconnect and reconnect your SSH session
2. test `docker ps`
3. test `sudo -n smartctl -H /dev/nvme0n1`
4. test `sudo -n /usr/local/bin/gputemps --json --once`
5. test `systemctl --failed`

If those work, the rig is usually ready for Fleet Health Check.

### Richer GPU temps with core / junction / VRAM

Plain `nvidia-smi` gives normal GPU core temperature, but not always junction and VRAM temperatures.

Fleet Health Check now supports ThomasBaruzier's public Linux tool:

- repo: <https://github.com/ThomasBaruzier/gddr6-core-junction-vram-temps>
- command used by the health check: `sudo -n gputemps --json --once`

If that command works on the rig, the health check can show:

- `GPU Temp` = core
- `GPU Junc` = junction
- `GPU VRAM` = VRAM / memory temp

The included installer downloads, builds, and installs that tool automatically.

If `gputemps` cannot run on a machine, the script still works and falls back to normal `nvidia-smi` core temp output.

### What you still need before the fleet script itself works

On the machine where you want to run Fleet Health Check, you still need:

- Python 3
- SSH client
- key-based SSH access to every rig you want to monitor
- the `RIGS` list in `fleet_health_check.py` updated with your own usernames / hosts / IPs

Edit the `RIGS` list in `fleet_health_check.py` and replace the example targets with your own:

```python
RIGS = [
    ("rig1-hostname", "user@192.168.1.10"),
    ("rig2-hostname", "user@192.168.1.11"),
]
```

## Key-based SSH access to all target machines

This script works best when the machine running it can SSH into every rig without interactive password prompts.

### 1. Generate an SSH key (if you do not already have one)

```bash
ssh-keygen -t ed25519 -C "fleet-health-check"
```

Accept the default path unless you have a reason not to.

### 2. Copy your public key to a target rig

The simplest normal way is:

```bash
ssh-copy-id user@192.168.1.10
```

Repeat for each target rig.

### 3. Test passwordless SSH

```bash
ssh user@192.168.1.10 hostname
```

If it prints the hostname without asking for a password, that rig is ready.

### One-command manual setup

If `ssh-copy-id` is unavailable, this does the same basic thing:

```bash
cat ~/.ssh/id_ed25519.pub | ssh user@192.168.1.10 'mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys'
```

That appends the current machine's public key to the target machine's `~/.ssh/authorized_keys` file.

### Why this matters

The fleet health check uses SSH in batch mode, so password prompts will break or hang checks. Key-based access keeps the script fast and non-interactive.

## Run

Default side-by-side table view:

```bash
python3 fleet_health_check.py
```

Vertical / one-rig-per-block view:

```bash
python3 fleet_health_check.py --vertical
```

Live watch mode, refreshing every 5 seconds:

```bash
python3 fleet_health_check.py --watch 5
```

The watch view now uses the improved lower-flicker redraw path, and with vertical mode it auto-fits to the current terminal width.

You can change the interval if you want, for example:

```bash
python3 fleet_health_check.py --watch 2
python3 fleet_health_check.py --watch 10
python3 fleet_health_check.py --watch 15
python3 fleet_health_check.py --watch 20
python3 fleet_health_check.py --watch 25
python3 fleet_health_check.py --watch 30
python3 fleet_health_check.py --watch 35
python3 fleet_health_check.py --watch 40
python3 fleet_health_check.py --watch 45
python3 fleet_health_check.py --watch 55
python3 fleet_health_check.py --watch 60
```

In vertical mode, the layout now auto-fits the current terminal width. On a narrow terminal it will fall back toward one rig per row instead of forcing 3 rigs side by side.

Flags-only quick glance view:

```bash
python3 fleet_health_check.py --flags
```

That mode is useful when you want just the most important per-rig signals without the full wall of detail.

The vertical mode is useful when you want a more readable grouped layout. It auto-fits to the terminal width, so on narrower screens it will fall back to fewer rigs per row.

## Notes

- This script is read-only.
- It does not restart services, change Docker, or modify hosts.
- Safe for inspection use while machines are active.
- The output is formatted as a side-by-side table for quicker fleet scanning.
- Colored terminal output is used automatically on normal Linux terminals to make statuses and flags easier to scan.

## First-setup fixes that new Vast rigs often need

On freshly installed rigs, the fleet health check may initially complain even when the host is basically fine.

The most common fixes are:

### 1. Let the SSH user read Docker state

If the script shows container state as `unknown` or `0` incorrectly, add the SSH user to the `docker` group:

```bash
sudo usermod -aG docker $USER
```

Then disconnect and reconnect your SSH session, and test:

```bash
docker ps
```

### 2. Install `smartmontools`

If the script shows `smartctl missing`, install it:

```bash
sudo apt update
sudo apt install -y smartmontools
```

### 3. Allow passwordless `smartctl` for the SSH user

If the script shows `sudo denied` for NVMe health, allow `smartctl` without a password:

```bash
echo "$USER ALL=(ALL) NOPASSWD: /usr/sbin/smartctl, /usr/bin/smartctl" | sudo tee /etc/sudoers.d/smartctl-fleet
sudo chmod 440 /etc/sudoers.d/smartctl-fleet
```

### 4. Fix Vast metrics service script permissions

Some newly installed Vast rigs can show a failing `vast_metrics.service` because the launcher script is not executable yet.

Fix it with:

```bash
sudo chmod +x /var/lib/vastai_kaalia/latest/launch_metrics_pusher.sh
sudo systemctl restart vast_metrics.service
systemctl status vast_metrics.service --no-pager -l
```

### 5. Clear stale failed-unit noise

If the script still shows failed services after you fixed the real problem, clear stale systemd failure state:

```bash
sudo systemctl reset-failed
systemctl --failed
```

If that comes back empty, rerun the fleet health check.

## If running containers shows `0` or `unknown`

If the SSH user cannot access Docker, the script may report `0` or `unknown` for running containers even when a renter container is actually running.

The clean fix is to add the SSH user to the `docker` group on each machine:

```bash
sudo usermod -aG docker $USER
```

Then disconnect and reconnect your SSH session, and test:

```bash
docker ps
```

If `docker ps` works without sudo, the health check script should report container counts correctly too.

## What `smartctl` / `smartmontools` does

`smartctl` reads SMART / health information reported by your SSD or NVMe drive.

For this fleet check, it is used as an early warning for storage problems such as:

- an SSD starting to fail
- SMART health warnings
- storage hardware instability
- problems that could eventually lead to corruption, crashes, or boot failure

It does **not** write to the disk just by checking health with commands like:

```bash
smartctl --version
sudo smartctl -H /dev/nvme0n1
```

Those are normal read/check commands.

## If NVMe health shows `smartctl missing`

Install `smartmontools` on the target rig:

```bash
sudo apt update && sudo apt install -y smartmontools
```

Test it:

```bash
smartctl --version
sudo smartctl -H /dev/nvme0n1
```

## `gputemps` caveat

ThomasBaruzier's tool may require extra host-side conditions on some machines, including things mentioned in that project such as:

- compatible GPU support
- `iomem=relaxed`
- Secure Boot disabled on some setups

If `gputemps` does not work on a given rig, Fleet Health Check will still run, but it may only show normal core temperature from `nvidia-smi` instead of junction / VRAM.

## If NVMe health shows `sudo denied`

The script uses `sudo -n smartctl -H ...` so it can stay non-interactive over SSH.

Grant passwordless sudo for `smartctl` only:

```bash
echo "$USER ALL=(ALL) NOPASSWD: /usr/sbin/smartctl" | sudo tee /etc/sudoers.d/smartctl-nopasswd
sudo chmod 440 /etc/sudoers.d/smartctl-nopasswd
```

Then test:

```bash
sudo -n smartctl -H /dev/nvme0n1
```

If that works, the fleet health check should show real NVMe SMART health instead of `smartctl missing`, `permission denied`, or `sudo denied`.

## Interpreting some common fields

- **RENTED**: the rig appears to be actively serving a live renter workload
- **LOW GPU LOAD**: renter/container activity exists but GPU utilization still looks suspiciously low
- **HOT**: GPU temperature reached 80°C or higher
- **PCIE X4**: at least one GPU is linked at x4 width, which can matter for debugging lane/bandwidth weirdness
- **WATCH DISK**: root disk usage is getting high
- **CLOCK UNSYNC**: system clock/NTP is not synced cleanly
- **NET WARN**: the quick DNS/ping sanity checks saw a problem
- **OOM SEEN**: recent out-of-memory event was found in logs
- **NIC EVENTS**: recent meaningful network adapter/link problem was seen in logs
- **RECENT REBOOT**: uptime is under 24 hours
- **PASSED** in NVMe: the drive reports healthy SMART status
- **Xid**: recent NVIDIA driver/GPU error log signal, if any

## What Xid is

Xid is NVIDIA's GPU driver error-reporting system.

If something goes wrong at the driver / GPU level, the kernel logs may contain lines such as:

- `NVRM: Xid ...`
- other NVIDIA/NVRM error lines

In this fleet check, the **Xid** column is a lightweight recent-log check. It helps surface whether a rig has logged recent NVIDIA-style GPU driver errors.

Typical meanings:

- **`none`** = no recent Xid/NVRM error found in the checked log window
- **actual log line shown** = the rig recently logged a GPU/NVIDIA driver error worth investigating
- **`no kernel log access`** = the script could not read enough kernel log output to check

This is useful for spotting rigs that look mostly alive but may have logged GPU instability, driver faults, or other hardware/driver weirdness.

## Why the newer added checks matter

These extra signals are there to help with the annoying cases where a rig looks mostly fine, but Vast or a renter behaves weirdly anyway.

- **Boot time** helps show whether a box silently rebooted recently.
- **NTP sync** helps catch clock drift / time issues.
- **Network sanity** helps catch boxes that are technically online but having weird network problems.
- **Recent OOM hint** helps spot cases where memory pressure killed something earlier.
- **Recent NIC event hint** helps surface real network link/reset trouble instead of making you guess.
- **GPU memory usage** helps show whether a renter workload is actually holding VRAM.
- **Container/workload hint** gives a rough clue about what Docker sees running, though random container names are only lightly useful.

In simple terms: the script now helps answer not just **"is the rig alive?"** but also **"did something weird happen recently that could explain this?"**

