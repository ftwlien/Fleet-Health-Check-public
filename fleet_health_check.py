#!/usr/bin/env python3
import argparse
import json
import os
import re
import sys
import time
import subprocess
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

RIGS = [
    ("rig1-hostname", "user@192.168.1.10"),
    ("rig2-hostname", "user@192.168.1.11"),
]

EXTRA_GPU_TEMP_CMD = os.environ.get('FLEET_GPU_TEMP_CMD', 'sudo -n gputemps --json --once')
RIG_TEMP_PROBES_PATH = Path('/home/bot1/.openclaw/workspace/dashboard/rig-temp-probes.json')

REMOTE_SCRIPT = r'''
set -e
python3 - <<'PY'
import subprocess

def run(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout.strip()

hostname = run('hostname')
uptime = run('uptime -p 2>/dev/null || uptime')
vast_active = run('systemctl is-active vastai 2>/dev/null || true')
docker_active = run('systemctl is-active docker 2>/dev/null || true')
vast_since = run('systemctl show vastai -p ActiveEnterTimestamp --value 2>/dev/null || true')
docker_ps = subprocess.run("docker ps --format '{{.Names}}'", shell=True, capture_output=True, text=True)
if docker_ps.returncode == 0:
    container_names = [x.strip() for x in docker_ps.stdout.splitlines() if x.strip()]
    running_containers = str(len(container_names))
    container_hint = ', '.join(container_names[:2]) if container_names else '--'
    docker_visible = 'yes'
else:
    running_containers = 'unknown'
    container_hint = 'unknown'
    docker_visible = 'no permission or unavailable'
gpu_temp = run("nvidia-smi --query-gpu=temperature.gpu --format=csv,noheader,nounits 2>/dev/null | paste -sd, -")
gpu_util = run("nvidia-smi --query-gpu=utilization.gpu --format=csv,noheader,nounits 2>/dev/null | paste -sd, -")
gpu_mem = run("nvidia-smi --query-gpu=memory.used,memory.total --format=csv,noheader,nounits 2>/dev/null | sed 's/, /\//g' | sed 's/$/ MiB/' | paste -sd, -")
gpu_power = run("nvidia-smi --query-gpu=power.draw --format=csv,noheader,nounits 2>/dev/null | paste -sd, -")
gpu_count = run("nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null | wc -l | tr -d ' '")
driver_version = run("nvidia-smi --query-gpu=driver_version --format=csv,noheader 2>/dev/null | head -n 1")
loadavg = run("python3 - <<'IN'\nwith open('/proc/loadavg') as f:\n    parts=f.read().split()\n    print(' '.join(parts[:3]))\nIN")
boot_time = run("uptime -s 2>/dev/null || who -b 2>/dev/null | sed 's/.*system boot[ ]*//' || true")
ntp_sync = run("timedatectl show -p NTPSynchronized --value 2>/dev/null || true")
default_route = run("ip route show default 2>/dev/null | head -n 1")
dns_test = run("getent hosts console.vast.ai >/dev/null 2>&1 && echo ok || echo fail")
ping_test = run("ping -c 1 -W 2 1.1.1.1 >/dev/null 2>&1 && echo ok || echo fail")
oom_recent = run("journalctl -k -n 400 --no-pager 2>/dev/null | grep -i -E 'out of memory|oom-killer|oom killer' | tail -n 1 | cut -c1-160 || true")
nic_recent = run("journalctl -k -n 400 --no-pager 2>/dev/null | grep -i -E 'NETDEV WATCHDOG|link is down|NIC Link is Down|reset adapter|tx timeout|timed out' | tail -n 1 | cut -c1-160 || true")
ram = run("python3 - <<'IN'\nimport subprocess\nout = subprocess.run(\"free -b\", shell=True, capture_output=True, text=True).stdout.splitlines()\nline = next((x for x in out if x.startswith('Mem:')), '')\nparts = line.split()\nif len(parts) >= 3:\n    used = int(parts[2]) / 1e9\n    total = int(parts[1]) / 1e9\n    pct = (used / total * 100) if total else 0\n    print(f'{used:.1f}G / {total:.1f}G ({pct:.0f}%)')\nelse:\n    print('unknown')\nIN")
disk_pct = run("df -P / | tail -n 1 | python3 -c \"import sys; p=sys.stdin.read().split(); print((p[4].rstrip('%')) if len(p)>=5 else '0')\"")
disk = run("df -h / | tail -n 1 | python3 -c \"import sys; p=sys.stdin.read().split(); print(f'{p[4]} used ({p[3]} free)' if len(p)>=5 else 'unknown')\"")
failed_services = run("systemctl --failed --no-legend 2>/dev/null | wc -l | tr -d ' ' || true")
pcie_width = run("nvidia-smi --query-gpu=pcie.link.width.current --format=csv,noheader,nounits 2>/dev/null | paste -sd, -")
reboot_required = run("if [ -f /var/run/reboot-required ]; then echo yes; else echo no; fi")
xid_recent = run("python3 - <<'IN'\nimport subprocess\ncmds = [\n    \"journalctl -k -n 400 --no-pager 2>/dev/null\",\n    \"dmesg 2>/dev/null | tail -n 400\",\n]\ntext = ''\nfor cmd in cmds:\n    proc = subprocess.run(cmd, shell=True, capture_output=True, text=True)\n    out = (proc.stdout or '').strip()\n    if out:\n        text = out\n        break\nif not text:\n    print('no kernel log access')\n    raise SystemExit\nlines = []\nfor line in text.splitlines():\n    s = line.strip()\n    if 'NVRM: Xid' in s or ('NVRM:' in s and 'Xid' in s):\n        lines.append(s)\nif not lines:\n    print('none')\n    raise SystemExit\nprint(lines[-1][:160])\nIN")
nvme_health = run("python3 - <<'IN'\nimport subprocess, glob\nif subprocess.run('command -v smartctl >/dev/null 2>&1', shell=True).returncode != 0:\n    print('smartctl missing')\n    raise SystemExit\ndevices = sorted(glob.glob('/dev/nvme*n1'))\nif not devices:\n    print('no nvme found')\n    raise SystemExit\nlast_stderr = ''\nfor dev in devices:\n    proc = subprocess.run(f'sudo -n smartctl -H {dev}', shell=True, capture_output=True, text=True)\n    out = (proc.stdout or '') + '\\n' + (proc.stderr or '')\n    if 'sudo:' in out and ('password is required' in out or 'a password is required' in out):\n        print('sudo denied')\n        raise SystemExit\n    if 'Permission denied' in out or 'Operation not permitted' in out:\n        print('permission denied')\n        raise SystemExit\n    for line in out.splitlines():\n        if 'SMART overall-health self-assessment test result:' in line:\n            print(line.split(':', 1)[1].strip())\n            raise SystemExit\n        if 'SMART Health Status:' in line:\n            print(line.split(':', 1)[1].strip())\n            raise SystemExit\n    last_stderr = out.strip()\nprint('unparsed' if last_stderr else 'unknown')\nIN")

print(f'HOSTNAME={hostname}')
print(f'UPTIME={uptime}')
print(f'VAST_ACTIVE={vast_active}')
print(f'DOCKER_ACTIVE={docker_active}')
print(f'VAST_SINCE={vast_since}')
print(f'RUNNING_CONTAINERS={running_containers}')
print(f'CONTAINER_HINT={container_hint}')
print(f'DOCKER_VISIBLE={docker_visible}')
print(f'GPU_TEMP={gpu_temp or "unknown"}')
print(f'GPU_UTIL={gpu_util or "unknown"}')
print(f'GPU_MEM={gpu_mem or "unknown"}')
print(f'GPU_POWER={gpu_power or "unknown"}')
print(f'GPU_COUNT={gpu_count or "unknown"}')
print(f'DRIVER_VERSION={driver_version or "unknown"}')
print(f'LOADAVG={loadavg or "unknown"}')
print(f'BOOT_TIME={boot_time or "unknown"}')
print(f'NTP_SYNC={ntp_sync or "unknown"}')
print(f'DEFAULT_ROUTE={default_route or "unknown"}')
print(f'DNS_TEST={dns_test or "unknown"}')
print(f'PING_TEST={ping_test or "unknown"}')
print(f'OOM_RECENT={oom_recent or "none"}')
print(f'NIC_RECENT={nic_recent or "none"}')
print(f'RAM={ram or "unknown"}')
print(f'PCIE_WIDTH={pcie_width or "unknown"}')
print(f'REBOOT_REQUIRED={reboot_required or "unknown"}')
print(f'XID_RECENT={xid_recent or "unknown"}')
print(f'NVME_HEALTH={nvme_health or "unknown"}')
print(f'DISK={disk or "unknown"}')
print(f'DISK_PCT={disk_pct or "0"}')
print(f'FAILED_SERVICES={failed_services or "0"}')
PY
'''


def run_rig(label, target):
    cmd = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=8', target, REMOTE_SCRIPT]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if proc.returncode != 0:
            return label, {'ok': False, 'error': (proc.stderr or proc.stdout).strip()}
        data = {}
        for line in proc.stdout.splitlines():
            if '=' in line:
                k, v = line.split('=', 1)
                data[k] = v.strip()
        extra = probe_extra_gpu_temps(target, data.get('HOSTNAME'))
        if extra.get('ok'):
            data.update(extra)
        data['ok'] = True
        return label, data
    except Exception as e:
        return label, {'ok': False, 'error': str(e)}


def split_csvish(value):
    return [part.strip() for part in str(value or '').split(',') if part.strip()]


def load_rig_temp_probe_config():
    try:
        payload = json.loads(RIG_TEMP_PROBES_PATH.read_text())
        return payload.get('machines') or {}
    except Exception:
        return {}


def probe_extra_gpu_temps(target, hostname=None):
    probe_cfg = load_rig_temp_probe_config()
    cmd_text = EXTRA_GPU_TEMP_CMD
    ssh_target = target
    if hostname and hostname in probe_cfg:
        cfg = probe_cfg.get(hostname) or {}
        cmd_text = cfg.get('command') or cmd_text
        ssh_target = cfg.get('ssh_target') or target
    cmd = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=8', ssh_target, cmd_text]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if proc.returncode != 0:
            return {'ok': False}
        text = (proc.stdout or '').strip()
        if not text:
            return {'ok': False}
        payload = json.loads(text)
        gpus = payload.get('gpus') or []
        core = []
        junction = []
        vram = []
        for gpu in gpus:
            if gpu.get('core') is not None:
                core.append(str(gpu.get('core')))
            if gpu.get('junction') is not None:
                junction.append(str(gpu.get('junction')))
            if gpu.get('vram') is not None:
                vram.append(str(gpu.get('vram')))
        return {
            'ok': True,
            'GPU_TEMP_CORE': ','.join(core) or 'unknown',
            'GPU_TEMP_JUNCTION': ','.join(junction) or 'unknown',
            'GPU_TEMP_VRAM': ','.join(vram) or 'unknown',
        }
    except Exception:
        return {'ok': False}


def format_dual_metric(value, suffix=''):
    parts = split_csvish(value)
    if not parts:
        return '--'
    return ' · '.join(f'{part}{suffix}' for part in parts)


def colorize_temp_metric(value, mid=70.0, hot=80.0, suffix='°C'):
    text = str(value or '').strip()
    if not text or text == '--':
        return '--'
    normalized = text.replace('·', ',')
    raw_parts = [part.strip() for part in normalized.split(',') if part.strip()]
    if not raw_parts:
        return '--'
    out = []
    for raw in raw_parts:
        cleaned = raw.replace(suffix, '').strip()
        label = f'{cleaned}{suffix}'
        try:
            temp = float(cleaned)
        except Exception:
            out.append(label)
            continue
        color = CYAN
        if temp >= hot:
            color = RED
        elif temp >= mid:
            color = YELLOW
        out.append(f'{color}{label}{RESET}')
    return ' · '.join(out)


def parse_max_temp(temp_str):
    vals = []
    for part in split_csvish(temp_str):
        try:
            vals.append(float(part))
        except Exception:
            pass
    return max(vals) if vals else 0.0


def uptime_hours(uptime_text):
    text = str(uptime_text or '').lower()
    total = 0.0
    m = re.search(r'(\d+)\s+week', text)
    if m:
        total += int(m.group(1)) * 24 * 7
    m = re.search(r'(\d+)\s+day', text)
    if m:
        total += int(m.group(1)) * 24
    m = re.search(r'(\d+)\s+hour', text)
    if m:
        total += int(m.group(1))
    m = re.search(r'(\d+)\s+minute', text)
    if m:
        total += int(m.group(1)) / 60.0
    return total


def classify(r):
    flags = []
    severity = 0

    if r.get('VAST_ACTIVE') != 'active':
        flags.append('VAST DOWN')
        severity = max(severity, 2)
    if r.get('DOCKER_ACTIVE') != 'active':
        flags.append('DOCKER DOWN')
        severity = max(severity, 2)

    docker_visible = (r.get('DOCKER_VISIBLE') or '').strip()
    raw_containers = (r.get('RUNNING_CONTAINERS') or '').strip()
    try:
        containers = int(raw_containers or 0)
    except Exception:
        containers = 0
    if docker_visible != 'yes' and raw_containers == 'unknown':
        flags.append('CONTAINERS UNKNOWN')
    else:
        flags.append('RENTED' if containers > 0 else 'IDLE')

    max_temp = parse_max_temp(r.get('GPU_TEMP', ''))
    if max_temp >= 80:
        flags.append('HOT')
        severity = max(severity, 2)

    try:
        disk_pct = int(float(r.get('DISK_PCT', '0') or 0))
    except Exception:
        disk_pct = 0
    if disk_pct >= 90:
        flags.append('LOW DISK')
        severity = max(severity, 2)
    elif disk_pct >= 80:
        flags.append('WATCH DISK')
        severity = max(severity, 1)

    try:
        failed_services = int(str(r.get('FAILED_SERVICES', '0') or '0').strip())
    except Exception:
        failed_services = 0
    if failed_services > 0:
        flags.append(f'{failed_services} FAILED SVCS')
        severity = max(severity, 1)

    gpu_utils = []
    for part in split_csvish(r.get('GPU_UTIL', '')):
        try:
            gpu_utils.append(float(part))
        except Exception:
            pass
    if containers > 0 and gpu_utils and max(gpu_utils) < 20:
        flags.append('LOW GPU LOAD')
        severity = max(severity, 1)

    pcie_parts = []
    for part in str(r.get('PCIE_WIDTH', '') or '').split(','):
        part = part.strip()
        if not part:
            continue
        try:
            pcie_parts.append(int(float(part)))
        except Exception:
            pass
    if pcie_parts and min(pcie_parts) <= 4:
        flags.append('PCIE X4')
        severity = max(severity, 1)

    if str(r.get('REBOOT_REQUIRED', 'no')).strip().lower() == 'yes':
        flags.append('REBOOT REQ')
        severity = max(severity, 1)

    if uptime_hours(r.get('UPTIME', '')) < 24:
        flags.append('RECENT REBOOT')
        severity = max(severity, 1)

    xid_recent = str(r.get('XID_RECENT', 'none') or 'none').strip().lower()
    if xid_recent not in ('none', 'unknown', 'no kernel log access'):
        flags.append('XID ERROR')
        severity = max(severity, 2)

    if str(r.get('NTP_SYNC', '')).strip().lower() not in ('yes', 'true'):
        flags.append('CLOCK UNSYNC')
        severity = max(severity, 1)
    if str(r.get('DNS_TEST', '')).strip().lower() != 'ok' or str(r.get('PING_TEST', '')).strip().lower() != 'ok':
        flags.append('NET WARN')
        severity = max(severity, 1)
    if str(r.get('OOM_RECENT', 'none') or 'none').strip().lower() not in ('', 'none'):
        flags.append('OOM SEEN')
        severity = max(severity, 1)
    if str(r.get('NIC_RECENT', 'none') or 'none').strip().lower() not in ('', 'none'):
        flags.append('NIC EVENTS')
        severity = max(severity, 1)

    nvme_health = str(r.get('NVME_HEALTH', 'unknown') or 'unknown').strip().lower()
    if nvme_health not in ('unknown', 'passed', 'ok'):
        flags.append('NVME WARN')
        severity = max(severity, 2)

    try:
        gpu_count = int(str(r.get('GPU_COUNT', '0') or '0').strip())
        expected = len(split_csvish(r.get('GPU_TEMP', '')))
        if expected and gpu_count and gpu_count != expected:
            flags.append('GPU COUNT MISMATCH')
            severity = max(severity, 2)
    except Exception:
        pass

    status = 'GOOD' if severity == 0 else ('WATCH' if severity == 1 else 'BAD')
    verdict = 'LIKELY HOST-OK / CHECK VAST'
    if 'HOT' in flags:
        verdict = 'LIKELY THERMAL ISSUE'
    elif 'LOW DISK' in flags or 'WATCH DISK' in flags or 'NVME WARN' in flags:
        verdict = 'LIKELY STORAGE ISSUE'
    elif 'NET WARN' in flags or 'NIC EVENTS' in flags or 'CLOCK UNSYNC' in flags:
        verdict = 'LIKELY NETWORK/TIME ISSUE'
    elif 'XID ERROR' in flags or 'GPU COUNT MISMATCH' in flags:
        verdict = 'LIKELY GPU/HOST ISSUE'
    return status, flags, verdict


ANSI_RE = re.compile(r'\x1b\[[0-9;]*m')
USE_COLOR = sys.stdout.isatty() and os.environ.get('NO_COLOR') is None
RESET = '\033[0m' if USE_COLOR else ''
BOLD = '\033[1m' if USE_COLOR else ''
DIM = '\033[2m' if USE_COLOR else ''
RED = '\033[91m' if USE_COLOR else ''
GREEN = '\033[92m' if USE_COLOR else ''
YELLOW = '\033[93m' if USE_COLOR else ''
BLUE = '\033[94m' if USE_COLOR else ''
MAGENTA = '\033[95m' if USE_COLOR else ''
ORANGE = '\033[38;5;208m' if USE_COLOR else ''
PURPLE = '\033[38;5;141m' if USE_COLOR else ''
CYAN = '\033[96m' if USE_COLOR else ''
WHITE = '\033[97m' if USE_COLOR else ''


def strip_ansi(text):
    return ANSI_RE.sub('', str(text))


def colorize_status(text):
    plain = str(text)
    if plain == 'GOOD':
        return f'{BOLD}{GREEN}{plain}{RESET}'
    if plain == 'WATCH':
        return f'{BOLD}{YELLOW}{plain}{RESET}'
    if plain == 'BAD':
        return f'{BOLD}{RED}{plain}{RESET}'
    return f'{CYAN}{plain}{RESET}'


def colorize_flags(text):
    parts = [p.strip() for p in str(text).split(',') if p.strip()]
    out = []
    for part in parts:
        upper = part.upper()
        color = WHITE
        if any(k in upper for k in ['SSH FAILED', 'HOT', 'NVME WARN']):
            color = RED
        elif any(k in upper for k in ['WATCH DISK', 'LOW GPU LOAD', 'PCIE X4', 'REBOOT REQ', 'FAILED SVCS']):
            color = YELLOW
        elif any(k in upper for k in ['RENTED']):
            color = MAGENTA
        elif any(k in upper for k in ['IDLE']):
            color = CYAN
        out.append(f'{color}{part}{RESET}')
    return ', '.join(out) if out else f'{CYAN}{text}{RESET}'


def colorize_header(text):
    return f'{BOLD}{BLUE}{text}{RESET}'


def fmt_cell(value, width):
    text = str(value if value not in (None, '') else '--')
    plain = strip_ansi(text)
    if len(plain) > width:
        if width <= 1:
            text = plain[:width]
            plain = text
        else:
            text = plain[:width - 1] + '…'
            plain = text
    pad = max(0, width - len(plain))
    return text + (' ' * pad)


def build_vertical_block(row):
    status_fields = ['Status', 'Flags']
    if strip_ansi(row.get('Verdict', '')).strip() not in ('', 'LIKELY HOST-OK / CHECK VAST'):
        status_fields.append('Verdict')
    sections = [
        ('Status', status_fields),
        ('Workload', ['Containers', 'Container Hint', 'GPU Temp', 'GPU Junc', 'GPU VRAM', 'GPU Util', 'GPU Mem', 'GPU Power']),
        ('Services', ['Vast', 'Docker']),
        ('System', ['Host', 'Driver', 'RAM', 'Load', 'Disk', 'Uptime', 'Boot', 'Reboot']),
        ('Health / Risk', ['PCIe', 'NVMe', 'Failed', 'Xid', 'NTP', 'Net']),
    ]
    lines = [f'{BOLD}{PURPLE}━━━━━━━━ [{row["Rig"].upper()}] ━━━━━━━━{RESET}', '']
    for section_name, field_names in sections:
        lines.append(f'  {colorize_header(section_name)}')
        for name in field_names:
            lines.append(f'    {DIM}{name}:{RESET} {row[name]}')
        lines.append('')
    while lines and lines[-1] == '':
        lines.pop()
    return lines


def print_side_by_side_blocks(rows, block_width=52, gap=4, cols=None):
    blocks = [build_vertical_block(row) for row in rows]
    if cols is None:
        try:
            term_width = os.get_terminal_size().columns
        except OSError:
            term_width = 180
        cols = max(1, term_width // (block_width + gap))
    for i in range(0, len(blocks), cols):
        group = blocks[i:i+cols]
        height = max(len(block) for block in group)
        padded = []
        for block in group:
            padded.append(block + [''] * (height - len(block)))
        for line_idx in range(height):
            print((' ' * gap).join(fmt_cell(padded[col_idx][line_idx], block_width) for col_idx in range(len(padded))))
        print()


def main():
    parser = argparse.ArgumentParser(description='Fleet Health Check')
    parser.add_argument('--vertical', action='store_true', help='show one rig per block instead of side-by-side table')
    parser.add_argument('--flags', action='store_true', help='show only the most important per-rig flags')
    parser.add_argument('--json', action='store_true', help='emit machine-readable JSON')
    parser.add_argument('--watch', nargs='?', const='5', help='refresh continuously every N seconds (default 5)')
    parser.add_argument('--watch-v2', nargs='?', const='5', dest='watch_v2', help='test watch-v2 renderer every N seconds (default 5)')
    args = parser.parse_args()

    results = {}
    with ThreadPoolExecutor(max_workers=len(RIGS) or 1) as ex:
        futs = [ex.submit(run_rig, label, target) for label, target in RIGS]
        for fut in as_completed(futs):
            label, data = fut.result()
            results[label] = data

    def collect_plain_rows():
        fresh_rows = []
        for label, _ in RIGS:
            r = results[label]
            if not r.get('ok'):
                fresh_rows.append({
                    'Rig': label,
                    'Status': 'BAD',
                    'Flags': 'SSH FAILED',
                    'Host': '--',
                    'Vast': '--',
                    'Docker': '--',
                    'Containers': '--',
                    'Container Hint': '--',
                    'GPU Temp': '--',
                    'GPU Junc': '--',
                    'GPU VRAM': '--',
                    'GPU Util': '--',
                    'GPU Mem': '--',
                    'GPU Power': '--',
                    'Driver': '--',
                    'RAM': '--',
                    'Boot': '--',
                    'NTP': '--',
                    'Net': '--',
                    'PCIe': '--',
                    'Reboot': '--',
                    'Xid': '--',
                    'NVMe': '--',
                    'Failed': '--',
                    'Load': '--',
                    'Disk': '--',
                    'Uptime': (r.get('error', 'unknown error') or '--'),
                    'Verdict': 'SSH FAILED / HOST UNREACHABLE',
                })
                continue
            status, flags, verdict = classify(r)
            fresh_rows.append({
                'Rig': label,
                'Status': status,
                'Flags': ', '.join(flags),
                'Host': r.get('HOSTNAME', '--'),
                'Vast': r.get('VAST_ACTIVE', '--'),
                'Docker': r.get('DOCKER_ACTIVE', '--'),
                'Containers': r.get('RUNNING_CONTAINERS', '--'),
                'Container Hint': r.get('CONTAINER_HINT', '--'),
                'GPU Temp': format_dual_metric(r.get('GPU_TEMP_CORE', r.get('GPU_TEMP', '--')), '°C'),
                'GPU Junc': format_dual_metric(r.get('GPU_TEMP_JUNCTION', '--'), '°C'),
                'GPU VRAM': format_dual_metric(r.get('GPU_TEMP_VRAM', '--'), '°C'),
                'GPU Util': format_dual_metric(r.get('GPU_UTIL', '--'), '%'),
                'GPU Mem': format_dual_metric(r.get('GPU_MEM', '--')),
                'GPU Power': format_dual_metric(r.get('GPU_POWER', '--'), 'W'),
                'Driver': r.get('DRIVER_VERSION', '--'),
                'RAM': r.get('RAM', '--'),
                'Boot': r.get('BOOT_TIME', '--'),
                'NTP': r.get('NTP_SYNC', '--'),
                'Net': f"dns:{r.get('DNS_TEST', '--')} ping:{r.get('PING_TEST', '--')}",
                'PCIe': f"x{r.get('PCIE_WIDTH', '--')}",
                'Reboot': r.get('REBOOT_REQUIRED', '--'),
                'Xid': r.get('XID_RECENT', '--'),
                'NVMe': r.get('NVME_HEALTH', '--'),
                'Failed': r.get('FAILED_SERVICES', '--'),
                'Load': r.get('LOADAVG', '--'),
                'Disk': r.get('DISK', '--'),
                'Uptime': r.get('UPTIME', '--'),
                'Verdict': verdict,
            })
        return fresh_rows

    rows = collect_plain_rows()

    columns = [
        ('Rig', 6),
        ('Status', 8),
        ('Flags', 22),
        ('Host', 16),
        ('Vast', 6),
        ('Docker', 6),
        ('Containers', 5),
        ('Container Hint', 16),
        ('GPU Temp', 12),
        ('GPU Junc', 12),
        ('GPU VRAM', 12),
        ('GPU Util', 10),
        ('GPU Mem', 16),
        ('GPU Power', 12),
        ('Driver', 10),
        ('RAM', 16),
        ('Boot', 14),
        ('NTP', 4),
        ('Net', 12),
        ('PCIe', 6),
        ('Reboot', 6),
        ('NVMe', 10),
        ('Failed', 6),
        ('Load', 12),
        ('Disk', 16),
        ('Uptime', 16),
        ('Verdict', 18),
        ('Xid', 18),
    ]

    for row in rows:
        row['Status'] = colorize_status(row['Status'])
        row['Flags'] = colorize_flags(row['Flags'])
        if row['Vast'] == 'active':
            row['Vast'] = f'{GREEN}{row["Vast"]}{RESET}'
        if row['Docker'] == 'active':
            row['Docker'] = f'{GREEN}{row["Docker"]}{RESET}'
        if row['Reboot'] == 'yes':
            row['Reboot'] = f'{YELLOW}{row["Reboot"]}{RESET}'
        elif row['Reboot'] == 'no':
            row['Reboot'] = f'{GREEN}{row["Reboot"]}{RESET}'
        if row['NVMe'] in ('PASSED', 'OK'):
            row['NVMe'] = f'{GREEN}{row["NVMe"]}{RESET}'
        elif row['NVMe'] not in ('--', 'unknown'):
            row['NVMe'] = f'{YELLOW}{row["NVMe"]}{RESET}'
        for key in ['Host', 'Containers', 'Container Hint', 'GPU Util', 'GPU Mem', 'GPU Power', 'Driver', 'RAM', 'Boot', 'Net', 'PCIe', 'Load', 'Disk']:
            if row.get(key) not in ('--', 'unknown', ''):
                row[key] = f'{CYAN}{row[key]}{RESET}'
        if row['GPU Temp'] not in ('--', 'unknown', ''):
            row['GPU Temp'] = colorize_temp_metric(strip_ansi(row['GPU Temp']))
        if row['GPU Junc'] not in ('--', 'unknown', ''):
            row['GPU Junc'] = colorize_temp_metric(strip_ansi(row['GPU Junc']), mid=80.0, hot=95.0)
        if row['GPU VRAM'] not in ('--', 'unknown', ''):
            row['GPU VRAM'] = colorize_temp_metric(strip_ansi(row['GPU VRAM']), mid=78.0, hot=90.0)
        if row['Uptime'] not in ('--', 'unknown'):
            row['Uptime'] = f'{DIM}{CYAN}{row["Uptime"]}{RESET}'

    flag_columns = [
        ('Rig', 6),
        ('Status', 8),
        ('Flags', 32),
        ('Host', 18),
        ('Vast', 8),
        ('Docker', 8),
        ('Containers', 10),
        ('Container Hint', 22),
        ('GPU Temp', 14),
        ('GPU Junc', 14),
        ('GPU VRAM', 14),
        ('GPU Util', 14),
        ('GPU Mem', 20),
    ]

    def render_normal_two_line_rows():
        top_cols = ['Rig', 'Status', 'Flags', 'Host', 'Vast', 'Docker', 'Containers', 'Container Hint']
        bot_cols = ['GPU Temp', 'GPU Junc', 'GPU VRAM', 'GPU Util', 'GPU Mem', 'GPU Power', 'PCIe', 'NVMe', 'Load', 'Uptime']
        top_widths = {
            'Rig': 16, 'Status': 8, 'Flags': 24, 'Host': 18, 'Vast': 6, 'Docker': 6, 'Containers': 5, 'Container Hint': 18
        }
        bot_widths = {
            'GPU Temp': 12, 'GPU Junc': 12, 'GPU VRAM': 12, 'GPU Util': 10, 'GPU Mem': 16, 'GPU Power': 12,
            'PCIe': 6, 'NVMe': 10, 'Load': 12, 'Uptime': 16
        }
        top_header = ' | '.join(fmt_cell(colorize_header(name), top_widths[name]) for name in top_cols)
        top_divider = '-+-'.join('-' * top_widths[name] for name in top_cols)
        bot_header = ' | '.join(fmt_cell(colorize_header(name), bot_widths[name]) for name in bot_cols)
        bot_divider = '-+-'.join('-' * bot_widths[name] for name in bot_cols)
        print(top_header)
        print(f'{DIM}{top_divider}{RESET}')
        for idx, row in enumerate(rows):
            print(' | '.join(fmt_cell(row[name], top_widths[name]) for name in top_cols))
            print(' | '.join(fmt_cell(row[name], bot_widths[name]) for name in bot_cols))
            if idx != len(rows) - 1:
                print(f'{DIM}{bot_divider}{RESET}')
                print()

    def render_once():
        if args.json:
            plain_rows = []
            for row in rows:
                plain_rows.append({k: strip_ansi(v) if isinstance(v, str) else v for k, v in row.items()})
            print(json.dumps({'rows': plain_rows}, indent=2))
            return

        print()
        print(f'{BOLD}{PURPLE}━━━━━━━━━━━━━━  FLEET HEALTH CHECK  ━━━━━━━━━━━━━━{RESET}')
        print()

        if args.flags:
            header = ' | '.join(fmt_cell(colorize_header(name), width) for name, width in flag_columns)
            divider = '-+-'.join('-' * width for _, width in flag_columns)
            print(header)
            print(f'{DIM}{divider}{RESET}')
            for row in rows:
                print(' | '.join(fmt_cell(row[name], width) for name, width in flag_columns))
            return

        if args.vertical:
            print_side_by_side_blocks(rows)
            return

        render_normal_two_line_rows()

    if not args.watch and not args.watch_v2:
        render_once()
        return

    watch_value = args.watch_v2 if args.watch_v2 is not None else args.watch
    try:
        interval = max(1.0, float(watch_value))
    except Exception:
        interval = 5.0

    if not args.flags and not args.json and not args.vertical:
        args.vertical = True

    use_watch_v2 = args.watch_v2 is not None
    if use_watch_v2:
        print(f'{YELLOW}watch-v2 test mode active{RESET}')

    last_render = None

    while True:
        results = {}
        with ThreadPoolExecutor(max_workers=len(RIGS) or 1) as ex:
            futs = [ex.submit(run_rig, label, target) for label, target in RIGS]
            for fut in as_completed(futs):
                label, data = fut.result()
                results[label] = data
        rows = collect_plain_rows()
        for row in rows:
            row['Status'] = colorize_status(row['Status'])
            row['Flags'] = colorize_flags(row['Flags'])
            if row['Vast'] == 'active':
                row['Vast'] = f'{GREEN}{row["Vast"]}{RESET}'
            if row['Docker'] == 'active':
                row['Docker'] = f'{GREEN}{row["Docker"]}{RESET}'
            if row['Reboot'] == 'yes':
                row['Reboot'] = f'{YELLOW}{row["Reboot"]}{RESET}'
            elif row['Reboot'] == 'no':
                row['Reboot'] = f'{GREEN}{row["Reboot"]}{RESET}'
            if row['NVMe'] in ('PASSED', 'OK'):
                row['NVMe'] = f'{GREEN}{row["NVMe"]}{RESET}'
            elif row['NVMe'] not in ('--', 'unknown'):
                row['NVMe'] = f'{YELLOW}{row["NVMe"]}{RESET}'
            for key in ['Host', 'Containers', 'Container Hint', 'GPU Util', 'GPU Mem', 'GPU Power', 'Driver', 'RAM', 'Boot', 'Net', 'PCIe', 'Load', 'Disk']:
                if row.get(key) not in ('--', 'unknown', ''):
                    row[key] = f'{CYAN}{row[key]}{RESET}'
            if row['GPU Temp'] not in ('--', 'unknown', ''):
                row['GPU Temp'] = colorize_temp_metric(strip_ansi(row['GPU Temp']))
            if row['GPU Junc'] not in ('--', 'unknown', ''):
                row['GPU Junc'] = colorize_temp_metric(strip_ansi(row['GPU Junc']), mid=80.0, hot=95.0)
            if row['GPU VRAM'] not in ('--', 'unknown', ''):
                row['GPU VRAM'] = colorize_temp_metric(strip_ansi(row['GPU VRAM']), mid=78.0, hot=90.0)
            if row['Uptime'] not in ('--', 'unknown'):
                row['Uptime'] = f'{DIM}{CYAN}{row["Uptime"]}{RESET}'
        frame_lines = []
        if args.flags:
            header = ' | '.join(fmt_cell(colorize_header(name), width) for name, width in flag_columns)
            divider = '-+-'.join('-' * width for _, width in flag_columns)
            frame_lines = [header, divider] + [' | '.join(fmt_cell(row[name], width) for name, width in flag_columns) for row in rows]
        elif args.vertical:
            for idx, row in enumerate(rows):
                frame_lines.extend(build_vertical_block(row))
                if idx != len(rows) - 1:
                    frame_lines.append('')
        else:
            top_cols = ['Rig', 'Status', 'Flags', 'Host', 'Vast', 'Docker', 'Containers', 'Container Hint']
            bot_cols = ['GPU Temp', 'GPU Junc', 'GPU VRAM', 'GPU Util', 'GPU Mem', 'GPU Power', 'PCIe', 'NVMe', 'Load', 'Uptime']
            top_widths = {'Rig': 16, 'Status': 8, 'Flags': 24, 'Host': 18, 'Vast': 6, 'Docker': 6, 'Containers': 5, 'Container Hint': 18}
            bot_widths = {'GPU Temp': 12, 'GPU Junc': 12, 'GPU VRAM': 12, 'GPU Util': 10, 'GPU Mem': 16, 'GPU Power': 12, 'PCIe': 6, 'NVMe': 10, 'Load': 12, 'Uptime': 16}
            top_header = ' | '.join(fmt_cell(colorize_header(name), top_widths[name]) for name in top_cols)
            top_divider = '-+-'.join('-' * top_widths[name] for name in top_cols)
            bot_divider = '-+-'.join('-' * bot_widths[name] for name in bot_cols)
            frame_lines = [top_header, top_divider]
            for idx, row in enumerate(rows):
                frame_lines.append(' | '.join(fmt_cell(row[name], top_widths[name]) for name in top_cols))
                frame_lines.append(' | '.join(fmt_cell(row[name], bot_widths[name]) for name in bot_cols))
                if idx != len(rows) - 1:
                    frame_lines.append(bot_divider)
                    frame_lines.append('')

        rendered_snapshot = '\n'.join(strip_ansi(line) for line in frame_lines)
        if use_watch_v2 and rendered_snapshot == last_render:
            time.sleep(interval)
            continue
        last_render = rendered_snapshot

        if sys.stdout.isatty():
            if use_watch_v2:
                sys.stdout.write('\033[H')
            else:
                sys.stdout.write('\033[H\033[2J\033[3J')
            sys.stdout.flush()
        render_once()
        print()
        print(f'{DIM}refreshing every {interval:g}s — Ctrl+C to stop{RESET}')
        time.sleep(interval)

if __name__ == '__main__':
    main()
