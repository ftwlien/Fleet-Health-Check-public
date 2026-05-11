#!/usr/bin/env python3
import argparse
import contextlib
import hashlib
import io
import json
import os
import re
import sys
import time
import subprocess
import urllib.request
import urllib.parse
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

RIGS = [
    ("rig1", "user@192.0.2.10"),
    ("rig2", "user@192.0.2.11"),
]

EXTRA_GPU_TEMP_CMD = os.environ.get('FLEET_GPU_TEMP_CMD', 'sudo -n gputemps --json --once')
RIG_TEMP_PROBES_PATH = Path(os.environ.get('FLEET_RIG_TEMP_PROBES_PATH', 'rig-temp-probes.json'))
SCRIPT_DIR = Path(__file__).resolve().parent
STATE_PATH = SCRIPT_DIR / '.fleet_health_telegram_watch_state.json'
DISPLAY_STATE_PATH = SCRIPT_DIR / '.fleet_health_display_state.json'
NIC_EVENTS_ACK_PATH = SCRIPT_DIR / '.fleet_health_nic_events_ack.json'
SECURITY_BASELINE_PATH = SCRIPT_DIR / '.fleet_health_security_baseline.json'
SECURITY_ALERT_STATE_PATH = SCRIPT_DIR / '.fleet_health_security_alert_state.json'


def load_env_file(path):
    try:
        lines = Path(path).read_text().splitlines()
    except Exception:
        return
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        if line.startswith('export '):
            line = line[len('export '):].strip()
        key, value = line.split('=', 1)
        key = key.strip()
        value = value.strip().strip('\"').strip("'")
        if key and value and key not in os.environ:
            os.environ[key] = value


# Let the alert bot work without manually sourcing env vars. .env wins over the
# placeholder helper file if both exist.
load_env_file(SCRIPT_DIR / '.env')
load_env_file(SCRIPT_DIR / '.fleet-alerts.env')

REMOTE_SCRIPT = r'''
set -e
python3 - <<'PY'
import grp
import hashlib
import json
import os
import pwd
import re
import subprocess
from pathlib import Path

def run(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout.strip()

def safe_sha256(path):
    p = Path(path)
    try:
        return hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else 'unreadable'
    except Exception:
        return 'permission-denied'

def safe_is_file(path):
    try:
        return Path(path).is_file()
    except Exception:
        return False

def safe_key_count(path):
    try:
        return len([x for x in Path(path).read_text().splitlines() if x.strip() and not x.strip().startswith('#')])
    except Exception:
        return -1

def scan_host_secret_presence():
    """Presence-only scan for persisted host secrets.

    Never returns secret values or matching lines; only categories, paths and
    counts. Runs via sudo so root histories, sudoers drop-ins, systemd env
    files, and installer resume state are covered.
    """
    scanner = r"""
import glob, json, pathlib, re
category_patterns = {
    'vast_api_key': [
        re.compile(r'(?i)\bVAST(_?AI)?_API_(KEY|TOKEN)\b'),
        re.compile(r'(?i)\bvast[_-]?api[_-]?(key|token)\b'),
        re.compile(r'(?i)(console\.vast\.ai/install|vast\.ai/install|vast-host-installer).*(api[_-]?key|machine[_-]?api[_-]?key|--api-key|--machine-api-key)'),
        re.compile(r'(?i)(api[_-]?key|machine[_-]?api[_-]?key|--api-key|--machine-api-key).*(console\.vast\.ai/install|vast\.ai/install|vast-host-installer)'),
        re.compile(r'(?i)\b(vastai|vast\.ai|vast|VAST)\b.*(api[_-]?key|api[_-]?token|--api-key|--machine-api-key|machine[_-]?api[_-]?key)'),
        re.compile(r'(?i)(api[_-]?key|api[_-]?token|--api-key|--machine-api-key|machine[_-]?api[_-]?key).*\b(vastai|vast\.ai|vast|VAST)\b'),
    ],
    'telegram_bot_token': [re.compile(r'(?i)\bTELEGRAM(_BOT)?_TOKEN\b'), re.compile(r'\b[0-9]{8,12}:[A-Za-z0-9_-]{25,}\b')],
    'openai_api_key': [re.compile(r'(?i)\bOPENAI_API_KEY\b'), re.compile(r'\bsk-[A-Za-z0-9_-]{24,}\b')],
    'anthropic_api_key': [re.compile(r'(?i)\bANTHROPIC_API_KEY\b'), re.compile(r'\bsk-ant-[A-Za-z0-9_-]{24,}\b')],
    'aws_access_key': [re.compile(r'(?i)\bAWS_(ACCESS_KEY_ID|SECRET_ACCESS_KEY|SESSION_TOKEN)\b'), re.compile(r'\bAKIA[0-9A-Z]{16}\b'), re.compile(r'\bASIA[0-9A-Z]{16}\b')],
    'huggingface_token': [re.compile(r'(?i)\b(HF_TOKEN|HUGGINGFACE(_HUB)?_(TOKEN|API_KEY|AUTH_TOKEN))\b'), re.compile(r'\bhf_[A-Za-z0-9]{30,}\b')],
    'github_token': [re.compile(r'(?i)\b(GITHUB_TOKEN|GH_TOKEN)\b'), re.compile(r'\bgh[pousr]_[A-Za-z0-9_]{30,}\b')],
    'private_key': [re.compile(r'-----BEGIN (OPENSSH|RSA|EC|DSA|PRIVATE) PRIVATE KEY-----')],
    'generic_secret_env': [re.compile(r'(?i)\b[A-Z0-9_]*(API[_-]?KEY|SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE[_-]?KEY)[A-Z0-9_]*\s*=\s*[^\s#]{12,}')],
}
globs = []
for home in ['/root'] + sorted(glob.glob('/home/*')):
    globs += [
        home + '/.bash_history', home + '/.zsh_history', home + '/.history',
        home + '/.profile', home + '/.bashrc', home + '/.bash_profile',
        home + '/.zprofile', home + '/.zshrc', home + '/.pam_environment',
        home + '/.env', home + '/*.env', home + '/.config/environment.d/*.conf', home + '/.config/systemd/user/*.service',
        home + '/.vast*', home + '/.config/vast*', home + '/.config/vast*/*',
    ]
globs += [
    '/etc/environment', '/etc/profile', '/etc/bash.bashrc', '/etc/profile.d/*.sh',
    '/etc/sudoers', '/etc/sudoers.d/*',
    '/etc/systemd/system/*.service', '/etc/systemd/system/*.env', '/etc/systemd/system/*.conf', '/etc/default/*',
    '/var/lib/vast-host-installer/resume.env', '/var/lib/vast-host-installer/*.env',
    '/opt/vast-host-installer/**/*.env', '/opt/vast-host-installer/**/*.service',
]
paths=[]; seen=set(); findings=[]; errors=[]; category_counts={k:0 for k in category_patterns}
for pat in globs:
    for p in glob.glob(pat, recursive=True):
        if p not in seen:
            seen.add(p); paths.append(p)
for p in paths:
    try:
        path=pathlib.Path(p)
        if not path.is_file() or path.is_symlink():
            continue
        raw=path.read_bytes()
        if b'\0' in raw[:4096]:
            continue
        text=raw.decode('utf-8','ignore')
        cats={}
        for line in text.splitlines():
            # Avoid flagging harmless examples/placeholders.
            if re.search(r'(?i)(your_|example|placeholder|changeme|xxxx|dummy|sample)', line):
                continue
            for cat, patterns in category_patterns.items():
                if any(rx.search(line) for rx in patterns):
                    cats[cat]=cats.get(cat,0)+1
        if cats:
            for cat, count in cats.items():
                category_counts[cat]=category_counts.get(cat,0)+count
            findings.append({'path': p, 'categories': sorted(cats), 'matches': sum(cats.values())})
    except Exception as e:
        errors.append({'path': p, 'error': type(e).__name__})
print(json.dumps({'status':'ok','count':len(findings),'category_counts':{k:v for k,v in category_counts.items() if v},'findings':findings[:50],'errors':errors[:10]}, sort_keys=True))
"""
    proc = subprocess.run(['sudo', '-n', 'python3', '-c', scanner], capture_output=True, text=True, timeout=20)
    if proc.returncode != 0:
        return {'status': 'scan_failed', 'count': 0, 'findings': [], 'error': (proc.stderr or proc.stdout or '').strip()[:160]}
    try:
        return json.loads((proc.stdout or '').strip().splitlines()[-1])
    except Exception:
        return {'status': 'parse_failed', 'count': 0, 'findings': [], 'error': 'scanner output parse failed'}

def scan_vast_api_key_presence():
    scan = scan_host_secret_presence()
    findings = []
    count = 0
    for item in scan.get('findings') or []:
        if 'vast_api_key' in (item.get('categories') or []):
            findings.append(item)
            count += 1
    return {'status': scan.get('status', 'ok'), 'count': count, 'findings': findings, 'errors': scan.get('errors') or []}

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
driver_candidate = run("python3 - <<'IN'\nimport re, subprocess\npackages = ['nvidia-driver-595-open','nvidia-driver-595','nvidia-driver-595-server-open','nvidia-headless-595','nvidia-utils-595']\nfor pkg in packages:\n    proc = subprocess.run(f'apt-cache policy {pkg} 2>/dev/null', shell=True, capture_output=True, text=True)\n    out = proc.stdout or ''\n    if not out:\n        continue\n    candidate = ''\n    for line in out.splitlines():\n        s = line.strip()\n        if s.startswith('Candidate:'):\n            candidate = s.split(':', 1)[1].strip()\n            break\n    if candidate and candidate != '(none)':\n        m = re.search(r'(\\d+\\.\\d+\\.\\d+)', candidate)\n        if m:\n            print(m.group(1))\n            raise SystemExit\nprint('unknown')\nIN")
driver_action = 'CHECK'
if driver_version and driver_version not in ('unknown', '--'):
    if driver_candidate and driver_candidate not in ('unknown', '--'):
        driver_action = 'OK' if driver_candidate == driver_version else 'UPDATE'
    else:
        driver_action = 'CHECK'
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
kernel_release = run('uname -r 2>/dev/null || true')
kernel_version = run('uname -v 2>/dev/null || true')
os_pretty = run(". /etc/os-release 2>/dev/null && printf '%s' \"${PRETTY_NAME:-unknown}\"")
kernel_pkg = run("dpkg-query -W -f='${Version}' linux-image-$(uname -r) 2>/dev/null || rpm -q --qf '%{VERSION}-%{RELEASE}' kernel 2>/dev/null | head -n 1 || true")
latest_kernel_available = run("python3 - <<'IN'\nimport re, subprocess\n\ndef run(cmd):\n    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout.strip()\n\nmeta_candidates = [\n    'linux-image-generic-hwe-22.04',\n    'linux-generic-hwe-22.04',\n    'linux-image-generic',\n    'linux-generic',\n]\nfor pkg in meta_candidates:\n    out = run(f\"apt-cache policy {pkg} 2>/dev/null\")\n    if not out:\n        continue\n    candidate = ''\n    for line in out.splitlines():\n        s = line.strip()\n        if s.startswith('Candidate:'):\n            candidate = s.split(':', 1)[1].strip()\n            break\n    if candidate and candidate != '(none)':\n        nums = re.findall(r'\\d+', candidate)\n        if len(nums) >= 4:\n            print(f\"{nums[0]}.{nums[1]}.{nums[2]}-{nums[3]}-generic\")\n            raise SystemExit\n        if len(nums) >= 3:\n            print(f\"{nums[0]}.{nums[1]}.{nums[2]}-generic\")\n            raise SystemExit\nout = run(\"apt list --upgradable 2>/dev/null | grep '^linux-generic-hwe-22.04\\|^linux-image-generic-hwe-22.04\\|^linux-generic\\|^linux-image-generic' | head -n 1\")\nnums = re.findall(r'\\d+', out)\nif len(nums) >= 4:\n    print(f\"{nums[0]}.{nums[1]}.{nums[2]}-{nums[3]}-generic\")\nelif len(nums) >= 3:\n    print(f\"{nums[0]}.{nums[1]}.{nums[2]}-generic\")\nIN")

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
print(f'DRIVER_LATEST={driver_candidate or "unknown"}')
print(f'DRIVER_ACTION={driver_action}')
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
print(f'KERNEL_RELEASE={kernel_release or "unknown"}')
print(f'KERNEL_VERSION={kernel_version or "unknown"}')
print(f'OS_PRETTY={os_pretty or "unknown"}')
print(f'KERNEL_PACKAGE={kernel_pkg or "unknown"}')
kernel_action = 'CHECK'
if latest_kernel_available and latest_kernel_available not in ('unknown', '--'):
    kernel_action = 'UPDATE+REBOOT' if latest_kernel_available != kernel_release else 'OK'
elif kernel_release and kernel_release not in ('unknown', '--'):
    kernel_action = 'UPDATE'
print(f'LATEST_KERNEL_AVAILABLE={latest_kernel_available or "unknown"}')
print(f'KERNEL_ACTION={kernel_action}')
auditd_active = run("systemctl is-active auditd 2>/dev/null || true")
aide_db = 'yes' if Path('/var/lib/aide/aide.db').exists() or Path('/var/lib/aide/aide.db.gz').exists() else 'no'
aide_helper = 'yes' if Path('/usr/local/bin/fleet-security-check').exists() else 'no'
print(f'FAILED_SERVICES={failed_services or "0"}')
print(f'AUDITD_ACTIVE={auditd_active or "unknown"}')
print(f'AIDE_DB={aide_db}')
print(f'FLEET_SECURITY_HELPER={aide_helper}')
print('SECURITY_JSON=' + json.dumps({
    'file_hashes': {
        '/etc/passwd': safe_sha256('/etc/passwd'),
        '/etc/shadow': safe_sha256('/etc/shadow'),
        '/etc/group': safe_sha256('/etc/group'),
        '/etc/sudoers': safe_sha256('/etc/sudoers'),
        '/etc/ssh/sshd_config': safe_sha256('/etc/ssh/sshd_config'),
    },
    'sudoers_dropins': [
        {'path': str(p), 'sha256': safe_sha256(str(p))}
        for p in sorted(Path('/etc/sudoers.d').glob('*')) if p.is_file()
    ] if Path('/etc/sudoers.d').exists() else [],
    'uid0_users': sorted([u.pw_name for u in pwd.getpwall() if u.pw_uid == 0]),
    'sudo_groups': {
        name: (sorted(grp.getgrnam(name).gr_mem) if any(g.gr_name == name for g in grp.getgrall()) else [])
        for name in ('sudo', 'wheel', 'docker')
    },
    'authorized_keys': [
        {
            'user': u.pw_name,
            'path': str(Path(u.pw_dir) / '.ssh' / 'authorized_keys'),
            'count': safe_key_count(str(Path(u.pw_dir) / '.ssh' / 'authorized_keys')),
            'uid': u.pw_uid,
        }
        for u in pwd.getpwall()
        if (u.pw_dir or '').startswith('/') and safe_is_file(str(Path(u.pw_dir) / '.ssh' / 'authorized_keys'))
    ],
    'listen_ports': [
        {'proto': parts[0], 'local': parts[4], 'proc': ' '.join(parts[6:]) if len(parts) >= 7 else ''}
        for parts in [line.split() for line in run("ss -ltnupH 2>/dev/null | head -n 120").splitlines()]
        if len(parts) >= 5
    ],
    'kernel_modules': [
        parts[0]
        for parts in [line.split() for line in run("lsmod 2>/dev/null | tail -n +2 | head -n 120").splitlines()]
        if parts
    ],
    'systemd_units': [
        {'unit': parts[0], 'state': parts[1]}
        for parts in [line.split() for line in run("systemctl list-unit-files --type=service --type=timer --no-pager --no-legend 2>/dev/null | head -n 200").splitlines()]
        if len(parts) >= 2
    ],
    'cron_files': [
        {'path': str(p), 'sha256': safe_sha256(str(p))}
        for p in ([Path('/etc/crontab')] + ([x for x in sorted(Path('/etc/cron.d').iterdir()) if x.is_file()] if Path('/etc/cron.d').exists() else []))
        if p.exists() and p.is_file()
    ],
    'stack_state': {
        'auditd_active': auditd_active or 'unknown',
        'aide_db': aide_db,
        'helper': aide_helper,
    },
    'host_secret_findings': scan_host_secret_presence(),
    'kernel_info': {
        'release': kernel_release or 'unknown',
        'version': kernel_version or 'unknown',
        'package': kernel_pkg or 'unknown',
        'latest_available': latest_kernel_available or 'unknown',
        'os': os_pretty or 'unknown',
    },
}, sort_keys=True))
PY
'''


def parse_security_json(text):
    value = str(text or '').strip()
    if not value:
        return {}
    try:
        return json.loads(value)
    except Exception:
        return {}


def run_rig(label, target):
    cmd = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=8', target, REMOTE_SCRIPT]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=45)
        if proc.returncode != 0:
            return label, {'ok': False, 'error': (proc.stderr or proc.stdout).strip()}
        data = {}
        for line in proc.stdout.splitlines():
            if '=' in line:
                k, v = line.split('=', 1)
                data[k] = v.strip()
        data['SECURITY'] = parse_security_json(data.get('SECURITY_JSON'))
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


def colorize_gpu_mem_metric(value, mid_pct=50.0, hot_pct=80.0):
    text = str(value or '').strip()
    if not text or text == '--':
        return '--'
    normalized = text.replace('·', ',')
    raw_parts = [part.strip() for part in normalized.split(',') if part.strip()]
    if not raw_parts:
        return '--'
    out = []
    for raw in raw_parts:
        label = raw
        m = re.search(r'(\d+(?:\.\d+)?)\s*/\s*(\d+(?:\.\d+)?)', raw)
        pct = None
        if m:
            try:
                used = float(m.group(1))
                total = float(m.group(2))
                pct = (used / total * 100.0) if total else None
            except Exception:
                pct = None
        color = CYAN
        if pct is not None:
            if pct >= hot_pct:
                color = RED
            elif pct >= mid_pct:
                color = YELLOW
            elif pct >= 5.0:
                color = GREEN
        out.append(f'{color}{label}{RESET}')
    return ' · '.join(out)


def colorize_gpu_power_metric(value, mid_w=250.0, hot_w=400.0):
    text = str(value or '').strip()
    if not text or text == '--':
        return '--'
    normalized = text.replace('·', ',')
    raw_parts = [part.strip() for part in normalized.split(',') if part.strip()]
    if not raw_parts:
        return '--'
    out = []
    for raw in raw_parts:
        label = raw
        cleaned = raw.replace('W', '').strip()
        try:
            watts = float(cleaned)
        except Exception:
            out.append(label)
            continue
        color = CYAN
        if watts >= hot_w:
            color = RED
        elif watts >= mid_w:
            color = YELLOW
        elif watts > 50.0:
            color = GREEN
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
        # Informational for this fleet: some rigs are intentionally/acceptably
        # running at x4. Show the flag, but don't downgrade status/verdict.
        flags.append('PCIE X4')

    if str(r.get('REBOOT_REQUIRED', 'no')).strip().lower() == 'yes':
        flags.append('REBOOT REQ')
        severity = max(severity, 1)

    recent_reboot = uptime_hours(r.get('UPTIME', '')) < 12
    if recent_reboot:
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
    nic_recent_raw = str(r.get('NIC_RECENT', 'none') or 'none').strip()
    net_unhealthy = str(r.get('DNS_TEST', '')).strip().lower() != 'ok' or str(r.get('PING_TEST', '')).strip().lower() != 'ok'
    if nic_recent_raw.lower() not in ('', 'none'):
        ack = load_nic_events_ack().get(str(r.get('HOSTNAME') or '').strip(), {})
        if net_unhealthy or (recent_reboot and ack.get('nic_recent') != nic_recent_raw):
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
    verdict = 'OK'
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
    if strip_ansi(row.get('Verdict', '')).strip() not in ('', 'OK'):
        status_fields.append('Verdict')
    sections = [
        ('Status', status_fields),
        ('Workload', ['Containers', 'Container Hint', 'GPU Temp', 'GPU Junc', 'GPU VRAM', 'GPU Power', 'GPU Mem']),
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



def load_json_file(path):
    try:
        return json.loads(path.read_text())
    except Exception:
        return {}


def save_json_file(path, data):
    path.write_text(json.dumps(data, indent=2, sort_keys=True))


def load_watch_state():
    return load_json_file(STATE_PATH)


def save_watch_state(state):
    save_json_file(STATE_PATH, state)


def split_flags_text(text):
    return [x.strip() for x in strip_ansi(str(text or '')).split(',') if x.strip()]


def status_and_verdict_from_flags(flags):
    severity = 0
    for flag in flags:
        upper = flag.upper()
        if any(k in upper for k in ['SSH FAILED', 'VAST DOWN', 'DOCKER DOWN', 'HOT', 'LOW DISK', 'NVME WARN', 'XID ERROR', 'GPU COUNT MISMATCH']):
            severity = max(severity, 2)
        elif any(k in upper for k in ['CONTAINERS UNKNOWN', 'WATCH DISK', 'FAILED SVCS', 'REBOOT REQ', 'RECENT REBOOT', 'CLOCK UNSYNC', 'NET WARN', 'OOM SEEN', 'NIC EVENTS']):
            severity = max(severity, 1)
    status = 'GOOD' if severity == 0 else ('WATCH' if severity == 1 else 'BAD')
    verdict = 'OK'
    if 'HOT' in flags:
        verdict = 'LIKELY THERMAL ISSUE'
    elif any(f in flags for f in ['LOW DISK', 'WATCH DISK', 'NVME WARN']):
        verdict = 'LIKELY STORAGE ISSUE'
    elif any(f in flags for f in ['NET WARN', 'NIC EVENTS', 'CLOCK UNSYNC']):
        verdict = 'LIKELY NETWORK/TIME ISSUE'
    elif any(f in flags for f in ['XID ERROR', 'GPU COUNT MISMATCH']):
        verdict = 'LIKELY GPU/HOST ISSUE'
    return status, verdict


def extract_max_temp_from_display(field_value):
    vals = []
    text = strip_ansi(str(field_value or '--'))
    for part in text.replace('·', ',').split(','):
        part = part.replace('°C', '').strip()
        if not part or part == '--':
            continue
        try:
            vals.append(float(part))
        except Exception:
            pass
    return max(vals) if vals else None


def stable_temp_hot(prev, key, value, threshold, hysteresis):
    state_key = f'{key}_hot_now'
    hot_prev = bool(prev.get(state_key))
    if value is None:
        hot_now = hot_prev
    elif value >= threshold:
        hot_now = True
    elif hot_prev and value >= (threshold - hysteresis):
        hot_now = True
    else:
        hot_now = False
    prev[state_key] = hot_now
    return hot_now


def apply_health_sheet_stability(rows):
    """Use the same stable rented/hot state model as Telegram alerts for display.

    Rental flips must survive multiple polls before the sheet changes. Temperature
    hot state uses the same thresholds and clear hysteresis as alerts, so cardtest
    and Telegram do not disagree or flicker on one bad sample. This uses a
    display-only state file so looking at the sheet cannot suppress Telegram alerts.
    """
    state = load_json_file(DISPLAY_STATE_PATH)
    stable_needed = max(2, int(os.environ.get('FLEET_TELEGRAM_STABLE_HITS', '2')))
    temp_clear_hysteresis = float(os.environ.get('FLEET_TEMP_CLEAR_HYSTERESIS', '3'))

    changed = False
    for row in rows:
        host = strip_ansi(str(row.get('Host') or row.get('Rig') or '')).strip()
        if not host:
            continue
        prev = state.get(host, {}) if isinstance(state.get(host, {}), dict) else {}

        raw_state = 'rented' if infer_rented(row) else 'idle'
        if not prev.get('state'):
            prev['state'] = raw_state
            prev['candidate'] = None
            prev['hits'] = 0
            changed = True
        elif prev.get('state') == raw_state:
            if prev.get('candidate') or int(prev.get('hits') or 0):
                changed = True
            prev['candidate'] = None
            prev['hits'] = 0
        else:
            if prev.get('candidate') == raw_state:
                prev['hits'] = int(prev.get('hits') or 0) + 1
            else:
                prev['candidate'] = raw_state
                prev['hits'] = 1
            changed = True
            if int(prev.get('hits') or 0) >= stable_needed:
                prev['state'] = raw_state
                prev['candidate'] = None
                prev['hits'] = 0

        core_hot = stable_temp_hot(prev, 'core', extract_max_temp_from_display(row.get('GPU Temp')), 80.0, temp_clear_hysteresis)
        junc_hot = stable_temp_hot(prev, 'junc', extract_max_temp_from_display(row.get('GPU Junc')), 95.0, temp_clear_hysteresis)
        vram_hot = stable_temp_hot(prev, 'vram', extract_max_temp_from_display(row.get('GPU VRAM')), 90.0, temp_clear_hysteresis)
        changed = True

        flags = [f for f in split_flags_text(row.get('Flags')) if f not in ('RENTED', 'IDLE', 'HOT')]
        flags.insert(0, 'RENTED' if prev.get('state') == 'rented' else 'IDLE')
        if core_hot or junc_hot or vram_hot:
            flags.append('HOT')
        if prev.get('state') != 'rented':
            flags = [f for f in flags if f != 'LOW GPU LOAD']

        row['Flags'] = ', '.join(flags)
        row['Status'], row['Verdict'] = status_and_verdict_from_flags(flags)
        state[host] = prev

    if changed:
        save_json_file(DISPLAY_STATE_PATH, state)
    return rows


def load_nic_events_ack():
    return load_json_file(NIC_EVENTS_ACK_PATH)


def save_nic_events_ack(data):
    save_json_file(NIC_EVENTS_ACK_PATH, data)


def load_security_baseline():
    return load_json_file(SECURITY_BASELINE_PATH)


def save_security_baseline(data):
    save_json_file(SECURITY_BASELINE_PATH, data)


def load_security_alert_state():
    return load_json_file(SECURITY_ALERT_STATE_PATH)


def save_security_alert_state(data):
    save_json_file(SECURITY_ALERT_STATE_PATH, data)


def normalize_security_payload(payload):
    payload = payload or {}
    return {
        'file_hashes': payload.get('file_hashes') or {},
        'sudoers_dropins': payload.get('sudoers_dropins') or [],
        'uid0_users': sorted(payload.get('uid0_users') or []),
        'sudo_groups': payload.get('sudo_groups') or {},
        'authorized_keys': payload.get('authorized_keys') or [],
        'listen_ports': payload.get('listen_ports') or [],
        'kernel_modules': payload.get('kernel_modules') or [],
        'systemd_units': payload.get('systemd_units') or [],
        'cron_files': payload.get('cron_files') or [],
        'stack_state': payload.get('stack_state') or {},
        'host_secret_findings': payload.get('host_secret_findings') or {},
        'vast_api_key_findings': payload.get('vast_api_key_findings') or {},
        'kernel_info': payload.get('kernel_info') or {},
        'cve_checks': payload.get('cve_checks') or {},
    }


def compute_security_summary(payload, baseline):
    payload = normalize_security_payload(payload)
    baseline = normalize_security_payload(baseline or payload)
    flags = []
    severity = 0
    details = {}
    strict_inventory_drift = os.environ.get('FLEET_STRICT_SECURITY_DRIFT', '0') == '1'

    current_uid0 = sorted(payload.get('uid0_users') or [])
    base_uid0 = sorted(baseline.get('uid0_users') or current_uid0)
    if current_uid0 != base_uid0:
        flags.append('UID0 DRIFT')
        details['uid0_added'] = [x for x in current_uid0 if x not in base_uid0]
        details['uid0_removed'] = [x for x in base_uid0 if x not in current_uid0]
        severity = max(severity, 2)
    extra_uid0 = [x for x in current_uid0 if x != 'root']
    if extra_uid0:
        flags.append('EXTRA UID0 USER')
        details['uid0_extra'] = extra_uid0
        severity = max(severity, 2)

    current_groups = payload.get('sudo_groups') or {}
    base_groups = baseline.get('sudo_groups') or current_groups
    for group_name in ('sudo', 'wheel', 'docker'):
        current_members = sorted(current_groups.get(group_name) or [])
        base_members = sorted(base_groups.get(group_name) or current_members)
        if current_members != base_members:
            added_members = [x for x in current_members if x not in base_members]
            removed_members = [x for x in base_members if x not in current_members]
            # Adding privileged users is scary. Removing old users is cleanup;
            # don't show it as drift unless strict mode is enabled.
            if added_members or strict_inventory_drift:
                flags.append(f'{group_name.upper()} DRIFT')
                details[f'{group_name}_added'] = added_members
                details[f'{group_name}_removed'] = removed_members
                if group_name in ('sudo', 'wheel') and added_members:
                    severity = max(severity, 2)
                else:
                    severity = max(severity, 1)
    sudo_members = sorted(current_groups.get('sudo') or [])
    if len(sudo_members) > 1:
        flags.append('EXTRA SUDO USER')
        details['sudo_extra'] = sudo_members
        details['sudo_count'] = len(sudo_members)
        severity = max(severity, 2)

    current_hashes = payload.get('file_hashes') or {}
    base_hashes = baseline.get('file_hashes') or current_hashes
    file_hash_severity = {
        # Do not alert on raw /etc/passwd or /etc/group hash drift. Those files
        # change for normal account/group metadata and caused scary false
        # positives. Real user risk is covered structurally by UID0 and
        # sudo/wheel/docker group membership checks above.
        '/etc/shadow': 2,          # password hash db changed: high priority
        '/etc/sudoers': 2,         # sudo policy changed: high priority
        '/etc/ssh/sshd_config': 2, # SSH daemon config changed: high priority
    }
    for path, sev in file_hash_severity.items():
        current_val = current_hashes.get(path)
        base_val = base_hashes.get(path) or current_val
        if current_val not in (None, 'permission-denied') and base_val not in (None, 'permission-denied') and current_val != base_val:
            short = Path(path).name.upper()
            flags.append(f'{short} CHANGED')
            details[f'hash_changed:{path}'] = {'before': base_val, 'after': current_val}
            severity = max(severity, sev)

    def normalize_list(items, key):
        out = []
        for item in items or []:
            if isinstance(item, dict):
                if key is None:
                    out.append(json.dumps(item, sort_keys=True))
                else:
                    out.append(item.get(key))
            else:
                out.append(item)
        return sorted([x for x in out if x])

    known_safe_sudoers_dropins = {
        '/etc/sudoers.d/fleet-health-check',
        '/etc/sudoers.d/gputemps-fleet-health-check',
        '/etc/sudoers.d/smartctl-fleet-health-check',
    }
    list_checks = [
        ('SSH KEYS DRIFT', 'authorized_keys', None, 2),
        ('SUDOERS.D DRIFT', 'sudoers_dropins', 'path', 2),
        ('CRON DRIFT', 'cron_files', 'path', 1),
    ]
    if strict_inventory_drift:
        # Very noisy on Vast hosts because rentals, drivers, updates and runtime
        # services legitimately change ports/modules/units. Keep available for
        # forensic/paranoid checks, but don't mark healthy rigs WATCH by default.
        list_checks.extend([
            ('PORT DRIFT', 'listen_ports', 'local', 1),
            ('KMOD DRIFT', 'kernel_modules', None, 1),
            ('SYSTEMD DRIFT', 'systemd_units', 'unit', 1),
        ])
    for flag_name, field_name, key_name, sev in list_checks:
        current_list = normalize_list(payload.get(field_name), key_name)
        base_list = normalize_list(baseline.get(field_name), key_name) or current_list
        added_items = [x for x in current_list if x not in base_list]
        removed_items = [x for x in base_list if x not in current_list]
        if flag_name == 'SUDOERS.D DRIFT':
            added_items = [x for x in added_items if x not in known_safe_sudoers_dropins]
        if added_items or removed_items:
            flags.append(flag_name)
            details[f'{field_name}_added'] = added_items
            details[f'{field_name}_removed'] = removed_items
            severity = max(severity, sev)

    current_stack = payload.get('stack_state') or {}
    base_stack = baseline.get('stack_state') or current_stack
    desired_stack = {
        'auditd_active': 'active',
        'aide_db': 'yes',
        'helper': 'yes',
    }
    for key, flag_name, sev in [
        ('auditd_active', 'AUDITD DRIFT', 1),
        ('aide_db', 'AIDE DB DRIFT', 1),
        ('helper', 'HELPER DRIFT', 1),
    ]:
        current_val = current_stack.get(key)
        base_val = base_stack.get(key, current_val)
        # Don't flag security improvements (inactive->active, no->yes), but do
        # flag missing desired security stack even if an old baseline also missed it.
        if current_val != desired_stack.get(key):
            flags.append(flag_name)
            details[f'stack:{key}'] = {'before': base_val, 'after': current_val, 'desired': desired_stack.get(key)}
            severity = max(severity, sev)

    host_secret_scan = payload.get('host_secret_findings') or {}
    # Compatibility for old baselines/payloads from the Vast-only scan.
    if not host_secret_scan and payload.get('vast_api_key_findings'):
        host_secret_scan = {'status': (payload.get('vast_api_key_findings') or {}).get('status', 'ok'), 'count': 0, 'category_counts': {}, 'findings': []}
    category_counts = host_secret_scan.get('category_counts') or {}
    vast_key_count = int(category_counts.get('vast_api_key') or 0)
    if vast_key_count > 0:
        flags.append('VAST API KEY STORED')
        details['vast_api_key_findings'] = {
            'count': vast_key_count,
            'paths': [x.get('path') for x in (host_secret_scan.get('findings') or []) if x.get('path') and 'vast_api_key' in (x.get('categories') or [])][:10],
        }
        severity = max(severity, 2)
    other_secret_categories = sorted([k for k, v in category_counts.items() if k != 'vast_api_key' and int(v or 0) > 0])
    if other_secret_categories:
        flags.append('HOST SECRET STORED')
        details['host_secret_findings'] = {
            'categories': other_secret_categories,
            'count': sum(int(category_counts.get(k) or 0) for k in other_secret_categories),
            'paths': [x.get('path') for x in (host_secret_scan.get('findings') or []) if x.get('path')][:10],
        }
        severity = max(severity, 2)
    if str(host_secret_scan.get('status') or 'ok') != 'ok':
        flags.append('SECRET SCAN FAILED')
        details['host_secret_scan'] = {'status': host_secret_scan.get('status'), 'error': host_secret_scan.get('error') or 'unknown'}
        severity = max(severity, 1)

    cve_checks = payload.get('cve_checks') or {}
    copy_fail = cve_checks.get('CVE-2026-31431') or {}
    copy_fail_status = str(copy_fail.get('status') or 'UNKNOWN').upper()
    if copy_fail_status in ('LIKELY_VULNERABLE', 'PATCHED_REBOOT_PENDING', 'UNKNOWN'):
        details['cve:CVE-2026-31431'] = {
            'status': copy_fail_status,
            'reason': copy_fail.get('reason') or 'no heuristic result',
            'confidence': copy_fail.get('confidence') or 'low',
            'kernel': (payload.get('kernel_info') or {}).get('release') or 'unknown',
            'latest_installed': copy_fail.get('latest_available_kernel') or 'unknown',
        }

    status = 'GOOD' if severity == 0 else ('WATCH' if severity == 1 else 'BAD')
    return status, flags, details


def maybe_send_security_alerts(security_rows):
    token = os.environ.get('TELEGRAM_BOT_TOKEN', '').strip()
    chat_id = os.environ.get('TELEGRAM_CHAT_ID', '').strip()
    if not token or not chat_id:
        return
    state = load_security_alert_state()
    now = int(time.time())
    default_cooldown = int(os.environ.get('FLEET_SECURITY_ALERT_COOLDOWN_SECONDS', str(60 * 60)))
    reminder_cooldown = int(os.environ.get('FLEET_SECURITY_REMINDER_SECONDS', str(12 * 60 * 60)))
    stable_needed = max(2, int(os.environ.get('FLEET_SECURITY_STABLE_HITS', os.environ.get('FLEET_TELEGRAM_STABLE_HITS', '2'))))
    startup_snapshot = not bool(state.get('_startup_snapshot_done'))

    security_meta = {
        'UID0 DRIFT': ('🚨', 'Root-equivalent users changed', 'uid0'),
        'EXTRA UID0 USER': ('🚨', 'Extra UID 0 user detected', 'uid0'),
        'SUDO DRIFT': ('🚨', 'Sudo group changed', 'sudo'),
        'EXTRA SUDO USER': ('🚨', 'Extra sudo user detected', 'sudo'),
        'WHEEL DRIFT': ('🚨', 'Wheel group changed', 'wheel'),
        'DOCKER DRIFT': ('🟠', 'Docker group changed', 'docker'),
        'PASSWD CHANGED': ('🚨', '/etc/passwd changed', 'file'),
        'SHADOW CHANGED': ('🚨', '/etc/shadow changed', 'file'),
        'GROUP CHANGED': ('🚨', '/etc/group changed', 'file'),
        'SUDOERS CHANGED': ('🚨', '/etc/sudoers changed', 'sudoers'),
        'SSHD_CONFIG CHANGED': ('🚨', 'SSH daemon config changed', 'ssh'),
        'SSH KEYS DRIFT': ('🚨', 'Authorized SSH keys changed', 'ssh'),
        'SUDOERS.D DRIFT': ('🚨', 'sudoers.d drop-ins changed', 'sudoers'),
        'PORT DRIFT': ('🚨', 'Listening ports changed', 'network'),
        'KMOD DRIFT': ('🚨', 'Kernel modules changed', 'kernel'),
        'SYSTEMD DRIFT': ('🟠', 'Systemd units changed', 'systemd'),
        'CRON DRIFT': ('🟠', 'Cron files changed', 'cron'),
        'AUDITD DRIFT': ('🟠', 'auditd state changed', 'stack'),
        'AIDE DB DRIFT': ('🟠', 'AIDE database state changed', 'stack'),
        'HELPER DRIFT': ('🟠', 'Fleet security helper changed', 'stack'),
        'VAST API KEY STORED': ('🚨', 'Stored Vast API key/installer command detected', 'secret'),
        'HOST SECRET STORED': ('🚨', 'Stored host secret detected', 'secret'),
        'SECRET SCAN FAILED': ('🟠', 'Stored host secret scan failed', 'secret'),
        'KERNEL UPDATE': ('🟠', 'Kernel security update available', 'kernel'),
        'NVIDIA DRIVER UPDATE': ('🟠', 'NVIDIA driver update available', 'driver'),
    }

    def compact(value, limit=5):
        if isinstance(value, list):
            vals = [str(x) for x in value if str(x)]
            if len(vals) > limit:
                return ', '.join(vals[:limit]) + f' … (+{len(vals) - limit})'
            return ', '.join(vals) if vals else 'none'
        if isinstance(value, dict):
            parts = []
            for k, v in value.items():
                if v not in (None, '', [], {}):
                    parts.append(f'{k}={v}')
            return ', '.join(parts[:limit]) if parts else 'none'
        return str(value) if value not in (None, '') else 'none'

    def detail_lines_for(flag, details, row):
        lines = []
        def add(label, value):
            text = compact(value)
            if text and text != 'none':
                lines.append(f'{label}: {text}')

        if flag == 'UID0 DRIFT':
            add('Added UID0', details.get('uid0_added'))
            add('Removed UID0', details.get('uid0_removed'))
            add('Current UID0', row.get('UID0'))
        elif flag == 'EXTRA UID0 USER':
            add('UID0 users', details.get('uid0_extra'))
        elif flag in ('SUDO DRIFT', 'WHEEL DRIFT', 'DOCKER DRIFT'):
            group = flag.split()[0].lower()
            add(f'{group} added', details.get(f'{group}_added'))
            add(f'{group} removed', details.get(f'{group}_removed'))
            add('Priv groups', row.get('Priv Groups'))
        elif flag == 'EXTRA SUDO USER':
            add('Sudo users', details.get('sudo_extra'))
            add('Sudo count', details.get('sudo_count'))
            add('Priv groups', row.get('Priv Groups'))
        elif flag == 'SSH KEYS DRIFT':
            add('Key files added/changed', details.get('authorized_keys_added'))
            add('Key files removed', details.get('authorized_keys_removed'))
            add('Key files now', row.get('Keys'))
        elif flag == 'SUDOERS.D DRIFT':
            add('Drop-ins added/changed', details.get('sudoers_dropins_added'))
            add('Drop-ins removed', details.get('sudoers_dropins_removed'))
        elif flag == 'PORT DRIFT':
            add('New ports', details.get('listen_ports_added'))
            add('Closed ports', details.get('listen_ports_removed'))
            add('Port count now', row.get('Ports'))
        elif flag == 'KMOD DRIFT':
            add('Modules added', details.get('kernel_modules_added'))
            add('Modules removed', details.get('kernel_modules_removed'))
            add('Module count now', row.get('Kmods'))
        elif flag == 'SYSTEMD DRIFT':
            add('Units added/changed', details.get('systemd_units_added'))
            add('Units removed', details.get('systemd_units_removed'))
        elif flag == 'CRON DRIFT':
            add('Cron added/changed', details.get('cron_files_added'))
            add('Cron removed', details.get('cron_files_removed'))
        elif flag in ('AUDITD DRIFT', 'AIDE DB DRIFT', 'HELPER DRIFT'):
            stack_key = {'AUDITD DRIFT': 'auditd_active', 'AIDE DB DRIFT': 'aide_db', 'HELPER DRIFT': 'helper'}[flag]
            add('State', details.get(f'stack:{stack_key}'))
        elif flag == 'VAST API KEY STORED':
            add('Stored key paths', (details.get('vast_api_key_findings') or {}).get('paths'))
            add('Match count', (details.get('vast_api_key_findings') or {}).get('count'))
        elif flag == 'HOST SECRET STORED':
            add('Categories', (details.get('host_secret_findings') or {}).get('categories'))
            add('Paths', (details.get('host_secret_findings') or {}).get('paths'))
            add('Match count', (details.get('host_secret_findings') or {}).get('count'))
        elif flag == 'SECRET SCAN FAILED':
            add('Scan state', details.get('host_secret_scan'))
        elif flag == 'KERNEL UPDATE':
            add('Kernel', details.get('kernel_update'))
        elif flag == 'NVIDIA DRIVER UPDATE':
            add('Driver', details.get('driver_update'))
        elif flag.endswith('CHANGED'):
            lines.append(flag)
        return lines[:4]

    initialized_bad = []
    initialized_watch = []

    for row in security_rows:
        host = strip_ansi(str(row.get('Rig') or '')).strip()
        if not host:
            continue
        status_now = strip_ansi(str(row.get('Status') or 'GOOD')).strip()
        flags_now = [x.strip() for x in strip_ansi(str(row.get('Flags') or '')).split(',') if x.strip() and x.strip() != 'BASELINE OK']
        details = row.get('_details') or {}
        prev = state.get(host, {})
        prev_status = prev.get('status')
        prev_flags = prev.get('flags') or []
        prev_signatures = prev.get('flag_signatures') or {}
        current_signatures = {flag: json.dumps(detail_lines_for(flag, details, row), sort_keys=True) for flag in flags_now}
        snapshot_sig = hashlib.sha1(json.dumps({
            'status': status_now,
            'flags': flags_now,
            'signatures': current_signatures,
        }, sort_keys=True).encode()).hexdigest()

        if startup_snapshot:
            if status_now == 'BAD':
                initialized_bad.append(host)
            elif status_now == 'WATCH':
                initialized_watch.append(host)
            state[host] = {
                'status': status_now,
                'flags': flags_now,
                'updated_at': now,
                'alert_sent_at': prev.get('alert_sent_at', {}),
                'flag_signatures': current_signatures,
                'snapshot_signature': snapshot_sig,
            }
            continue

        committed_sig = prev.get('snapshot_signature') or hashlib.sha1(json.dumps({
            'status': prev_status or 'GOOD',
            'flags': prev_flags,
            'signatures': prev_signatures,
        }, sort_keys=True).encode()).hexdigest()
        if snapshot_sig != committed_sig:
            candidate = prev.get('candidate_snapshot') or {}
            if candidate.get('signature') == snapshot_sig:
                candidate['hits'] = int(candidate.get('hits') or 0) + 1
            else:
                candidate = {'signature': snapshot_sig, 'hits': 1, 'first_seen_at': now}
            if int(candidate.get('hits') or 0) < stable_needed:
                prev['candidate_snapshot'] = candidate
                prev['candidate_status'] = status_now
                prev['candidate_flags'] = flags_now
                prev['candidate_flag_signatures'] = current_signatures
                prev['updated_at'] = int(prev.get('updated_at') or now)
                state[host] = prev
                continue
            prev.pop('candidate_snapshot', None)
            prev.pop('candidate_status', None)
            prev.pop('candidate_flags', None)
            prev.pop('candidate_flag_signatures', None)

        added = [f for f in flags_now if f not in prev_flags]
        changed = [f for f in flags_now if f in prev_flags and prev_signatures.get(f) != current_signatures.get(f)]
        removed = [f for f in prev_flags if f not in flags_now]

        messages = []
        if added or changed:
            severity = '🚨' if status_now == 'BAD' or any(security_meta.get(f, ('🚨', '', ''))[0] == '🚨' for f in added + changed) else '🟠'
            lines = [
                f'{severity} Fleet Security Alert',
                '',
                f'Rig: {host}',
                f'Status: {status_now}',
            ]
            if added:
                lines.append(f'New flags: {", ".join(added[:10])}')
            if changed:
                lines.append(f'Changed details: {", ".join(changed[:10])}')
            detail_budget = 10
            for flag in (added + changed):
                if detail_budget <= 0:
                    break
                title = security_meta.get(flag, ('', flag, ''))[1]
                lines.append(f'- {flag}: {title}')
                detail_budget -= 1
                for dline in detail_lines_for(flag, details, row):
                    if detail_budget <= 0:
                        break
                    lines.append(f'  {dline}')
                    detail_budget -= 1
            remaining = [f for f in flags_now if f not in added + changed]
            if remaining:
                lines.append(f'Other active flags: {", ".join(remaining[:10])}')
            sig = hashlib.sha1(json.dumps({f: current_signatures.get(f) for f in added + changed}, sort_keys=True).encode()).hexdigest()[:12]
            messages.append((f'security_batch:{host}:{sig}', default_cooldown, '\n'.join(lines)))

        if prev_status in ('WATCH', 'BAD') and status_now == 'GOOD':
            messages.append(('security:cleared', 0, f"🟢 Fleet Security Alert\n\nRig: {host}\nSecurity drift cleared\nStatus: GOOD"))
        elif removed:
            messages.append((
                'security:flags_removed:' + hashlib.sha1(','.join(sorted(removed)).encode()).hexdigest()[:12],
                default_cooldown,
                f"🟢 Fleet Security Alert\n\nRig: {host}\nCleared flags: {', '.join(removed)}\nRemaining: {', '.join(flags_now) if flags_now else 'none'}"
            ))

        prev_updated_at = int(prev.get('updated_at') or 0)
        if status_now in ('WATCH', 'BAD') and not added and not changed and prev_status == status_now and flags_now and prev_updated_at > 0 and (now - prev_updated_at) >= reminder_cooldown:
            messages.append((
                'security:reminder:' + hashlib.sha1(','.join(sorted(flags_now)).encode()).hexdigest()[:12],
                reminder_cooldown,
                f"{'🚨' if status_now == 'BAD' else '🟠'} Fleet Security Reminder\n\nRig: {host}\nStatus still {status_now}\nActive flags: {', '.join(flags_now[:12])}"
            ))

        send_alerts_with_dedupe(messages, prev, token, chat_id, now)
        state[host] = {
            'status': status_now,
            'flags': flags_now,
            'updated_at': now,
            'alert_sent_at': prev.get('alert_sent_at', {}),
            'flag_signatures': current_signatures,
            'snapshot_signature': snapshot_sig,
        }

    if startup_snapshot:
        state['_startup_snapshot_done'] = True
        summary_parts = []
        if initialized_bad:
            summary_parts.append(f"BAD: {len(initialized_bad)} ({', '.join(initialized_bad[:8])}{'…' if len(initialized_bad) > 8 else ''})")
        if initialized_watch:
            summary_parts.append(f"WATCH: {len(initialized_watch)} ({', '.join(initialized_watch[:8])}{'…' if len(initialized_watch) > 8 else ''})")
        # One startup message max, and only if there are active issues.
        if summary_parts and os.environ.get('FLEET_SECURITY_STARTUP_SUMMARY', '1') != '0':
            pseudo_prev = state.setdefault('_global', {})
            send_alerts_with_dedupe([
                ('security:startup_summary', 24 * 60 * 60, '📋 Fleet Security Watch initialized\n\nSeeded current security state. Future changes will alert.\n' + '\n'.join(summary_parts))
            ], pseudo_prev, token, chat_id, now)
    save_security_alert_state(state)

def infer_rented(row):
    flags = strip_ansi(row.get('Flags', ''))
    return 'RENTED' in flags


def send_telegram_message(text, token, chat_id):
    data = urllib.parse.urlencode({'chat_id': chat_id, 'text': text}).encode()
    req = urllib.request.Request(f'https://api.telegram.org/bot{token}/sendMessage', data=data)
    with urllib.request.urlopen(req, timeout=20) as resp:
        resp.read()


def alert_allowed(prev, key, now, cooldown_seconds):
    sent = prev.setdefault('alert_sent_at', {})
    last = int(sent.get(key) or 0)
    return last == 0 or (now - last) >= cooldown_seconds


def mark_alert_sent(prev, key, now):
    sent = prev.setdefault('alert_sent_at', {})
    sent[key] = now


def send_alerts_with_dedupe(alerts, prev, token, chat_id, now):
    sent_count = 0
    for key, cooldown, msg in alerts:
        if not alert_allowed(prev, key, now, cooldown):
            continue
        try:
            send_telegram_message(msg, token, chat_id)
            mark_alert_sent(prev, key, now)
            prev['last_alert_at'] = now
            sent_count += 1
        except Exception as e:
            prev['last_error'] = str(e)
            break
    return sent_count


def maybe_send_rent_transition_alerts(rows):
    token = os.environ.get('TELEGRAM_BOT_TOKEN', '').strip()
    chat_id = os.environ.get('TELEGRAM_CHAT_ID', '').strip()
    if not token or not chat_id:
        print('telegram-watch: missing TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID', file=sys.stderr)
        return

    state = load_watch_state()
    stable_needed = max(2, int(os.environ.get('FLEET_TELEGRAM_STABLE_HITS', '2')))
    now = int(time.time())
    startup_snapshot = not bool(state.get('_startup_snapshot_done'))

    default_cooldown = int(os.environ.get('FLEET_ALERT_COOLDOWN_SECONDS', str(30 * 60)))
    repeat_temp_cooldown = int(os.environ.get('FLEET_TEMP_REPEAT_COOLDOWN_SECONDS', str(60 * 60)))
    temp_rise_step = float(os.environ.get('FLEET_TEMP_RISE_STEP', '2'))
    temp_clear_hysteresis = float(os.environ.get('FLEET_TEMP_CLEAR_HYSTERESIS', '3'))

    # Host-health flags are deliberately conservative: a single SSH/ping/API
    # hiccup should not page Andy. Rental transitions already have their own
    # stability check; temp alerts have threshold+hysteresis. These host flags
    # require stable_needed consecutive polls before alerting/clearing.
    important_flags = {
        'VAST DOWN',
        'DOCKER DOWN',
        'CONTAINERS UNKNOWN',
        'LOW DISK',
        'WATCH DISK',
        'NVME WARN',
        'XID ERROR',
        'GPU COUNT MISMATCH',
        'REBOOT REQ',
        'FAILED SVCS',
        'NIC EVENTS',
        'NET WARN',
        'CLOCK UNSYNC',
    }
    important_flag_prefixes = ('FAILED SVCS',)
    noisy_flags = {'LOW GPU LOAD'}

    def is_important_flag(flag):
        return flag in important_flags or any(flag.endswith(' ' + suffix) or flag == suffix for suffix in important_flag_prefixes)

    def extract_max_temp(field_value):
        vals = []
        text = strip_ansi(str(field_value or '--'))
        for part in text.replace('·', ',').split(','):
            part = part.replace('°C', '').strip()
            if not part or part == '--':
                continue
            try:
                vals.append(float(part))
            except Exception:
                pass
        return (max(vals) if vals else None), text

    def temp_alerts(prev, host, metric_key, label, emoji_hot, emoji_clear, value, threshold, temp_summary, flags_text):
        alerts = []
        hot_key = f'{metric_key}_hot_now'
        alert_temp_key = f'{metric_key}_last_alert_temp'
        alert_at_key = f'{metric_key}_last_alert_at'
        hot_hits_key = f'{metric_key}_hot_candidate_hits'
        clear_hits_key = f'{metric_key}_clear_candidate_hits'
        clear_key = f'temp_clear:{metric_key}'
        hot_alert_key = f'temp_hot:{metric_key}'

        # Still conservative, but don't wait around if it is genuinely cooking.
        emergency_threshold = threshold + float(os.environ.get('FLEET_TEMP_EMERGENCY_MARGIN', '5'))
        hot_now = value is not None and value >= threshold
        emergency_hot = value is not None and value >= emergency_threshold
        clear_now = value is not None and value < (threshold - temp_clear_hysteresis)
        hot_prev = bool(prev.get(hot_key))
        last_alert_temp = prev.get(alert_temp_key)
        last_alert_at = int(prev.get(alert_at_key) or 0)

        if hot_now:
            prev[hot_hits_key] = int(prev.get(hot_hits_key) or 0) + 1
            prev[clear_hits_key] = 0
        elif clear_now:
            prev[clear_hits_key] = int(prev.get(clear_hits_key) or 0) + 1
            prev[hot_hits_key] = 0
        else:
            prev[hot_hits_key] = 0
            prev[clear_hits_key] = 0

        confirmed_hot = hot_now and (emergency_hot or int(prev.get(hot_hits_key) or 0) >= stable_needed)
        confirmed_clear = clear_now and int(prev.get(clear_hits_key) or 0) >= stable_needed

        should_hot_alert = False
        reason = 'threshold crossed'
        if confirmed_hot:
            if not hot_prev:
                should_hot_alert = True
                reason = 'emergency threshold crossed' if emergency_hot else f'threshold confirmed across {stable_needed} checks'
            else:
                try:
                    rose_enough = last_alert_temp is not None and value >= float(last_alert_temp) + temp_rise_step
                except Exception:
                    rose_enough = False
                repeat_due = last_alert_at > 0 and (now - last_alert_at) >= repeat_temp_cooldown
                if rose_enough and (emergency_hot or int(prev.get(hot_hits_key) or 0) >= stable_needed):
                    should_hot_alert = True
                    reason = f'increased by ≥{temp_rise_step:g}°C since last alert'
                elif repeat_due:
                    should_hot_alert = True
                    reason = f'still hot after {repeat_temp_cooldown // 60}m'

            if should_hot_alert:
                prev[alert_temp_key] = value
                prev[alert_at_key] = now
                cooldown = 0 if (not hot_prev or reason.startswith('increased') or reason.startswith('emergency')) else repeat_temp_cooldown
                alerts.append((
                    hot_alert_key,
                    cooldown,
                    f"{emoji_hot} Fleet Health Check\n\nRig: {host}\n{label} temp alert\nReason: {reason}\n{temp_summary}\nFlags: {flags_text}"
                ))
            prev[hot_key] = True
        elif hot_prev and confirmed_clear:
            prev[hot_key] = False
            alerts.append((
                clear_key,
                default_cooldown,
                f"{emoji_clear} Fleet Health Check\n\nRig: {host}\n{label} temp back below threshold\nConfirmed clear: {stable_needed} checks\n{temp_summary}\nNote: other temp alerts may still be active."
            ))
        return alerts

    for row in rows:
        host = strip_ansi(str(row.get('Host') or row.get('Rig') or '')).strip()
        if not host:
            continue

        cur = 'rented' if infer_rented(row) else 'idle'
        prev = state.get(host, {})
        alerts = []
        try:
            cur_containers = int(strip_ansi(row.get('Containers', '0')) or 0)
        except Exception:
            cur_containers = 0
        if not prev.get('state'):
            # Seed first observed state silently, then only alert on confirmed changes.
            prev['state'] = cur
            prev['candidate'] = None
            prev['hits'] = 0
            prev['last_containers'] = cur_containers
            prev['state_containers'] = cur_containers

        # Rental state changes must be stable across multiple polls so short API
        # glitches do not create fake rented/stopped messages.
        if prev.get('state') == cur:
            prev['candidate'] = None
            prev['hits'] = 0
        else:
            if prev.get('candidate') == cur:
                prev['hits'] = int(prev.get('hits', 0)) + 1
            else:
                prev['candidate'] = cur
                prev['hits'] = 1

        if prev.get('candidate') == cur and int(prev.get('hits', 0)) >= stable_needed:
            old_state = prev.get('state')
            prev['state'] = cur
            prev['candidate'] = None
            prev['hits'] = 0
            if old_state and old_state != cur:
                try:
                    old_containers = int(prev.get('state_containers', prev.get('last_containers', 0)) or 0)
                except Exception:
                    old_containers = 0
                delta = cur_containers - old_containers
                if cur == 'rented':
                    title = '🟢 Fleet Health rental started'
                    status_text = 'Rented / containers running'
                else:
                    title = '🔴 Fleet Health rental ended'
                    status_text = 'All containers stopped / idle'
                base = [
                    title,
                    '',
                    f'Rig: {host}',
                    f'Status: {status_text}',
                    f'Change: Containers: {old_containers} → {cur_containers} ({delta:+d})',
                    f'Temps: core {strip_ansi(row.get("GPU Temp", "--"))} | junc {strip_ansi(row.get("GPU Junc", "--"))} | vram {strip_ansi(row.get("GPU VRAM", "--"))}',
                    f'Flags: {strip_ansi(row.get("Flags", "--"))}',
                ]
                alerts.append((f'rent:{cur}', 0, '\n'.join(base)))
                prev['state_containers'] = cur_containers

        status_now = strip_ansi(str(row.get('Status', '--')))
        flags_now = [x.strip() for x in strip_ansi(str(row.get('Flags', ''))).split(',') if x.strip()]
        flags_now_clean = [f for f in flags_now if f not in noisy_flags]
        flags_prev = prev.get('last_flags') or []

        important_now = [f for f in flags_now_clean if is_important_flag(f)]

        stable_state = prev.setdefault('stable_flag_state', {})
        stable_added = []
        stable_removed = []
        for flag in sorted(set(important_now) | set(stable_state.keys())):
            if not is_important_flag(flag):
                continue
            active_now = flag in important_now
            st = stable_state.setdefault(flag, {'state': flag in flags_prev, 'candidate': None, 'hits': 0})
            active_state = bool(st.get('state'))
            if active_now == active_state:
                st['candidate'] = None
                st['hits'] = 0
                continue
            candidate = 'active' if active_now else 'clear'
            if st.get('candidate') == candidate:
                st['hits'] = int(st.get('hits') or 0) + 1
            else:
                st['candidate'] = candidate
                st['hits'] = 1
            if int(st.get('hits') or 0) >= stable_needed:
                st['state'] = active_now
                st['candidate'] = None
                st['hits'] = 0
                if active_now:
                    stable_added.append(flag)
                else:
                    stable_removed.append(flag)

        for flag in stable_added:
            alerts.append((
                f'flag_stable_added:{flag}',
                default_cooldown,
                f"🟠 Fleet Health Check\n\nRig: {host}\nHost alert: {flag}\nConfirmed: {stable_needed} checks in a row\nStatus: {status_now}\nAll flags: {', '.join(flags_now_clean) if flags_now_clean else '--'}\nVerdict: {strip_ansi(row.get('Verdict', '--'))}"
            ))
        for flag in stable_removed:
            alerts.append((
                f'flag_stable_removed:{flag}',
                default_cooldown,
                f"🟢 Fleet Health Check\n\nRig: {host}\nHost alert cleared: {flag}\nConfirmed clear: {stable_needed} checks in a row\nRemaining flags: {', '.join(flags_now_clean) if flags_now_clean else 'none'}"
            ))
        prev['last_flags'] = flags_now_clean
        prev['last_status'] = status_now
        prev['last_containers'] = cur_containers

        if startup_snapshot:
            # First watcher poll seeds current state only. Do not page on startup:
            # one transient sample during process start caused scary false alerts.
            pass

        core_max, core_text = extract_max_temp(row.get('GPU Temp', '--'))
        junc_max, junc_text = extract_max_temp(row.get('GPU Junc', '--'))
        vram_max, vram_text = extract_max_temp(row.get('GPU VRAM', '--'))
        temp_summary = f"Core: {core_text} | Junction: {junc_text} | VRAM: {vram_text}"
        flags_text = strip_ansi(row.get('Flags', '--'))

        alerts.extend(temp_alerts(prev, host, 'core', 'GPU Core', '🔥', '🧊', core_max, 80.0, temp_summary, flags_text))
        alerts.extend(temp_alerts(prev, host, 'junc', 'GPU Junction', '🌋', '❄️', junc_max, 95.0, temp_summary, flags_text))
        alerts.extend(temp_alerts(prev, host, 'vram', 'GPU VRAM', '🧠', '✅', vram_max, 90.0, temp_summary, flags_text))

        send_alerts_with_dedupe(alerts, prev, token, chat_id, now)
        state[host] = prev

    state['_startup_snapshot_done'] = True
    save_watch_state(state)

def ack_current_nic_events(rows):
    ack = load_nic_events_ack()
    for row in rows:
        host = strip_ansi(str(row.get('Host') or row.get('Rig') or '')).strip()
        nic_text = strip_ansi(str(row.get('Net') or '')).strip()
        status_text = strip_ansi(str(row.get('Status') or '')).strip()
        flags = [x.strip() for x in strip_ansi(str(row.get('Flags') or '')).split(',') if x.strip()]
        if not host:
            continue
        ack[host] = {
            'status': status_text,
            'flags': flags,
            'net': nic_text,
            'nic_recent': strip_ansi(str(row.get('NIC Recent') or '')).strip(),
            'acked_at': int(time.time()),
        }
    save_nic_events_ack(ack)

def main():
    parser = argparse.ArgumentParser(description='Fleet Health Check')
    parser.add_argument('--vertical', action='store_true', help='show one rig per block instead of side-by-side table')
    parser.add_argument('--flags', action='store_true', help='show only the most important per-rig flags')
    parser.add_argument('--card', action='store_true', help='show polished wide health + security card view')
    parser.add_argument('--cardtest', action='store_true', help='show the default split dashboard explicitly')
    parser.add_argument('--public-labels', action='store_true', help='with --card/--cardtest, anonymize rig labels as rig1..rigN')
    parser.add_argument('--json', action='store_true', help='emit machine-readable JSON')
    parser.add_argument('--watch', nargs='?', const='5', help='refresh continuously every N seconds (default 5)')
    parser.add_argument('--watch-v2', nargs='?', const='5', dest='watch_v2', help='test watch-v2 renderer every N seconds (default 5)')
    parser.add_argument('--switch-v2', nargs='?', const='5', dest='watch_v2', help=argparse.SUPPRESS)  # backwards/typo alias
    parser.add_argument('--telegram-watch', nargs='?', const='60', dest='telegram_watch', help='poll and send Telegram rent started/stopped alerts every N seconds (default 60)')
    parser.add_argument('--telegram-bot', nargs='?', const='60', dest='telegram_bot', help='run rental + security Telegram alert bot every N seconds (default 60)')
    parser.add_argument('--ack-nic-events', action='store_true', help='acknowledge current NIC events snapshot on all machines')
    parser.add_argument('--security', action='store_true', help='show dedicated security drift view')
    parser.add_argument('--security-baseline', choices=['save'], help='save current security snapshot as baseline')
    parser.add_argument('--security-telegram-watch', nargs='?', const='60', dest='security_telegram_watch', help='poll and send Telegram security drift alerts every N seconds (default 60)')
    args = parser.parse_args()

    if args.watch or args.watch_v2 is not None:
        msg = f'collecting fleet data from {len(RIGS)} rigs — first render appears after SSH checks finish…'
        if sys.stdout.isatty():
            sys.stdout.write('\033[H\033[2J\033[3J')
            sys.stdout.flush()
        print(f'{DIM}{msg}{RESET}', flush=True)

    results = {}
    with ThreadPoolExecutor(max_workers=len(RIGS) or 1) as ex:
        futs = [ex.submit(run_rig, label, target) for label, target in RIGS]
        for fut in as_completed(futs):
            label, data = fut.result()
            results[label] = data

    def collect_plain_rows(results_map=None):
        results_map = results if results_map is None else results_map
        fresh_rows = []
        for label, _ in RIGS:
            r = results_map[label]
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
                    'GPU Power': '--',
                    'GPU Mem': '--',
                    'Driver': '--',
                    'RAM': '--',
                    'Boot': '--',
                    'NTP': '--',
                    'Net': '--',
                    'NIC Recent': '--',
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
                'GPU Power': format_dual_metric(r.get('GPU_POWER', '--'), 'W'),
                'GPU Mem': format_dual_metric(r.get('GPU_MEM', '--')),
                'Driver': r.get('DRIVER_VERSION', '--'),
                'RAM': r.get('RAM', '--'),
                'Boot': r.get('BOOT_TIME', '--'),
                'NTP': r.get('NTP_SYNC', '--'),
                'Net': f"dns:{r.get('DNS_TEST', '--')} ping:{r.get('PING_TEST', '--')}",
                'NIC Recent': r.get('NIC_RECENT', '--'),
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

    rows = apply_health_sheet_stability(collect_plain_rows())

    if args.ack_nic_events:
        ack_current_nic_events(rows)
        print('Acknowledged current NIC event snapshot for all machines.')
        return

    if args.security_baseline == 'save':
        baseline = {}
        for label, data in results.items():
            if data.get('ok'):
                baseline[label] = data.get('SECURITY') or {}
        save_security_baseline(baseline)
        print(f'Saved security baseline to {SECURITY_BASELINE_PATH}')
        return

    security_baseline = load_security_baseline()

    def collect_security_rows(results_map=None):
        results_map = results if results_map is None else results_map
        security_rows = []
        for label, _ in RIGS:
            r = results_map[label]
            if not r.get('ok'):
                security_rows.append({
                    'Rig': label,
                    'Status': 'BAD',
                    'Flags': 'SSH FAILED',
                    'Kernel': '--',
                    'Latest': '--',
                    'CVE': '--',
                    'Drv': '--',
                    'Drv Latest': '--',
                    'GPU': '--',
                    'UID0': '--',
                    'Priv Groups': '--',
                    'Auditd': '--',
                    'AIDE DB': '--',
                    'Helper': '--',
                    'API Keys': '--',
                    'Secrets': '--',
                    'Keys': '--',
                    'Ports': '--',
                    'Kmods': '--',
                    'Systemd': '--',
                    'Cron': '--',
                })
                continue
            payload = r.get('SECURITY') or {}
            base = security_baseline.get(label) or payload
            sec_status, sec_flags, sec_details = compute_security_summary(payload, base)
            kernel_info = payload.get('kernel_info') or {}
            kernel_action = r.get('KERNEL_ACTION') or kernel_info.get('action') or 'CHECK'
            driver_action = r.get('DRIVER_ACTION') or 'CHECK'
            driver_version = r.get('DRIVER_VERSION') or '--'
            driver_latest = r.get('DRIVER_LATEST') or '--'
            latest_available = r.get('LATEST_KERNEL_AVAILABLE') or kernel_info.get('latest_available') or '--'
            running_kernel = r.get('KERNEL_RELEASE') or kernel_info.get('release') or 'unknown'
            # Kernel/NVIDIA update posture is already shown in the CVE/GPU columns.
            # Do not turn it into a security flag/status by default, or healthy rigs
            # become WATCH just because updates are available.
            if sec_flags and sec_status == 'GOOD':
                sec_status = 'BAD'
            group_counts = []
            for g in ('sudo', 'wheel', 'docker'):
                members = (payload.get('sudo_groups') or {}).get(g) or []
                if members:
                    group_counts.append(f'{g}:{len(members)}')
            host_secret_scan = payload.get('host_secret_findings') or {}
            secret_counts = host_secret_scan.get('category_counts') or {}
            secret_count = sum(int(v or 0) for v in secret_counts.values())
            vast_key_count = int(secret_counts.get('vast_api_key') or 0)
            vast_key_display = 'FAIL' if str(host_secret_scan.get('status') or 'ok') != 'ok' else str(vast_key_count)
            secret_display = 'FAIL' if str(host_secret_scan.get('status') or 'ok') != 'ok' else str(secret_count)
            security_rows.append({
                'Rig': label,
                'Status': sec_status,
                'Flags': ', '.join(sec_flags) if sec_flags else 'BASELINE OK',
                'Kernel': str(running_kernel)[:18],
                'Latest': str(latest_available)[:18],
                'CVE': str(kernel_action)[:14],
                'Drv': str(driver_version)[:10],
                'Drv Latest': str(driver_latest)[:10],
                'GPU': str(driver_action)[:10],
                'UID0': ', '.join(payload.get('uid0_users') or []) or '--',
                'Priv Groups': ' · '.join(group_counts) or '--',
                'Keys': str(len(payload.get('authorized_keys') or [])),
                'Ports': str(len(payload.get('listen_ports') or [])),
                'Kmods': str(len(payload.get('kernel_modules') or [])),
                'Systemd': str(len(payload.get('systemd_units') or [])),
                'Cron': str(len(payload.get('cron_files') or [])),
                'Auditd': r.get('AUDITD_ACTIVE', '--'),
                'AIDE DB': r.get('AIDE_DB', '--'),
                'Helper': r.get('FLEET_SECURITY_HELPER', '--'),
                'API Keys': vast_key_display,
                'Secrets': secret_display,
                '_details': sec_details,
            })
        return security_rows

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
        ('GPU Power', 12),
        ('GPU Mem', 16),
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
        for key in ['Host', 'Containers', 'Container Hint', 'Driver', 'RAM', 'Boot', 'Net', 'PCIe', 'Load', 'Disk']:
            if row.get(key) not in ('--', 'unknown', ''):
                row[key] = f'{CYAN}{row[key]}{RESET}'
        if row['GPU Temp'] not in ('--', 'unknown', ''):
            row['GPU Temp'] = colorize_temp_metric(strip_ansi(row['GPU Temp']))
        if row['GPU Junc'] not in ('--', 'unknown', ''):
            row['GPU Junc'] = colorize_temp_metric(strip_ansi(row['GPU Junc']), mid=80.0, hot=95.0)
        if row['GPU VRAM'] not in ('--', 'unknown', ''):
            row['GPU VRAM'] = colorize_temp_metric(strip_ansi(row['GPU VRAM']), mid=78.0, hot=90.0)
        if row['GPU Mem'] not in ('--', 'unknown', ''):
            row['GPU Mem'] = colorize_gpu_mem_metric(strip_ansi(row['GPU Mem']))
        if row['GPU Power'] not in ('--', 'unknown', ''):
            row['GPU Power'] = colorize_gpu_power_metric(strip_ansi(row['GPU Power']))
        if row['Uptime'] not in ('--', 'unknown'):
            row['Uptime'] = f'{CYAN}{row["Uptime"]}{RESET}'

    security_columns = [
        ('Rig', 16),
        ('Status', 8),
        ('Flags', 22),
        ('Kernel', 18),
        ('Latest', 18),
        ('CVE', 14),
        ('Drv', 10),
        ('Drv Latest', 10),
        ('GPU', 10),
        ('UID0', 12),
        ('Priv Groups', 18),
        ('Auditd', 8),
        ('AIDE DB', 7),
        ('Helper', 7),
        ('API Keys', 8),
        ('Secrets', 7),
        ('Keys', 5),
        ('Ports', 5),
        ('Kmods', 5),
        ('Systemd', 7),
        ('Cron', 5),
    ]

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
        ('GPU Power', 12),
        ('GPU Mem', 20),
    ]


    card_health_columns = [
        ('Rig', 8), ('Status', 8), ('Flags', 26), ('Vast', 6), ('Docker', 6), ('Cont', 5),
        ('GPU Temp', 12), ('GPU Junc', 12), ('GPU Power', 18), ('GPU Mem', 20), ('Disk', 16), ('PCIe', 6), ('Driver', 10),
    ]
    card_security_columns = [
        ('Rig', 8), ('Status', 8), ('Flags', 26), ('Kernel', 18), ('CVE', 14), ('Drv', 10),
        ('GPU', 10), ('Priv Groups', 18), ('Auditd', 8), ('AIDE', 7), ('API Keys', 8), ('Secrets', 7), ('Ports', 5),
    ]

    def card_line(width, left='╭', fill='─', right='╮'):
        return f'{CYAN}{left}{fill * max(0, width - 2)}{right}{RESET}'

    def card_title(text, width):
        plain = strip_ansi(text)
        side = max(0, width - len(plain) - 4)
        return f'{CYAN}╭─ {BOLD}{WHITE}{plain}{RESET}{CYAN} {"─" * side}╮{RESET}'

    def expand_columns(columns, rendered_rows):
        expanded = []
        for name, width in columns:
            max_content = len(strip_ansi(name))
            for row in rendered_rows:
                max_content = max(max_content, len(strip_ansi(row.get(name, '--'))))
            expanded.append((name, max(width, max_content)))
        return expanded

    def card_width(columns):
        return sum(w for _, w in columns) + (3 * (len(columns) - 1)) + 4

    def card_table(title, subtitle, columns, rendered_rows):
        columns = expand_columns(columns, rendered_rows)
        width = card_width(columns)
        lines = ['', card_title(title, width)]
        lines.append(f'{CYAN}│{RESET} {DIM}{fmt_cell(subtitle, width - 4)}{RESET} {CYAN}│{RESET}')
        lines.append(f'{CYAN}├{"─" * (width - 2)}┤{RESET}')
        header = ' | '.join(fmt_cell(colorize_header(name), w) for name, w in columns)
        divider = '-+-'.join('-' * w for _, w in columns)
        lines.append(f'{CYAN}│{RESET} {header} {CYAN}│{RESET}')
        lines.append(f'{CYAN}│{RESET} {DIM}{divider}{RESET} {CYAN}│{RESET}')
        for row in rendered_rows:
            lines.append(f'{CYAN}│{RESET} ' + ' | '.join(fmt_cell(row.get(name, '--'), w) for name, w in columns) + f' {CYAN}│{RESET}')
        lines.append(f'{CYAN}╰{"─" * (width - 2)}╯{RESET}')
        return lines

    def render_card():
        public = bool(args.public_labels)
        card_health_rows = []
        for idx, row in enumerate(rows, start=1):
            card_health_rows.append({
                'Rig': f'rig{idx}' if public else row.get('Rig', f'rig{idx}'),
                'Status': row.get('Status', '--'),
                'Flags': row.get('Flags', '--'),
                'Vast': row.get('Vast', '--'),
                'Docker': row.get('Docker', '--'),
                'Cont': row.get('Containers', '--'),
                'GPU Temp': row.get('GPU Temp', '--'),
                'GPU Junc': row.get('GPU Junc', '--'),
                'GPU Power': row.get('GPU Power', '--'),
                'GPU Mem': row.get('GPU Mem', '--'),
                'Disk': row.get('Disk', '--'),
                'PCIe': row.get('PCIe', '--'),
                'Driver': row.get('Driver', '--'),
            })

        security_rows = collect_security_rows()
        for row in security_rows:
            row['Status'] = colorize_status(row['Status'])
            row['Flags'] = colorize_flags(row['Flags'])
            for key in ['UID0', 'Priv Groups', 'API Keys', 'Secrets', 'Keys', 'Ports', 'Kmods', 'Systemd', 'Cron']:
                if row.get(key) not in ('--', 'unknown', ''):
                    row[key] = f'{CYAN}{row[key]}{RESET}'
            if row.get('Auditd') == 'active':
                row['Auditd'] = f'{GREEN}{row["Auditd"]}{RESET}'
            if row.get('AIDE DB') == 'yes':
                row['AIDE DB'] = f'{GREEN}{row["AIDE DB"]}{RESET}'
            if row.get('GPU') == 'OK':
                row['GPU'] = f'{GREEN}{row["GPU"]}{RESET}'
            elif row.get('GPU') == 'UPDATE':
                row['GPU'] = f'{YELLOW}{row["GPU"]}{RESET}'
            if row.get('CVE') == 'OK':
                row['CVE'] = f'{GREEN}{row["CVE"]}{RESET}'
            elif 'UPDATE' in str(row.get('CVE')):
                row['CVE'] = f'{YELLOW}{row["CVE"]}{RESET}'

        card_security_rows = []
        for idx, row in enumerate(security_rows, start=1):
            card_security_rows.append({
                'Rig': f'rig{idx}' if public else row.get('Rig', f'rig{idx}'),
                'Status': row.get('Status', '--'),
                'Flags': row.get('Flags', '--'),
                'Kernel': row.get('Kernel', '--'),
                'CVE': row.get('CVE', '--'),
                'Drv': row.get('Drv', '--'),
                'GPU': row.get('GPU', '--'),
                'Priv Groups': row.get('Priv Groups', '--'),
                'Auditd': row.get('Auditd', '--'),
                'AIDE': row.get('AIDE DB', '--'),
                'API Keys': row.get('API Keys', '--'),
                'Secrets': row.get('Secrets', '--'),
                'Ports': row.get('Ports', '--'),
            })

        expanded_health_columns = expand_columns(card_health_columns, card_health_rows)
        expanded_security_columns = expand_columns(card_security_columns, card_security_rows)
        max_width = max(card_width(expanded_health_columns), card_width(expanded_security_columns))
        print()
        print(f'{BOLD}{CYAN}╭{"─" * (max_width - 2)}╮{RESET}')
        title = 'VAST FLEET HEALTH + SECURITY'
        sub = ('anonymized rig1..rigN · ' if public else '') + f'{len(rows)} rigs · health + security posture in one view'
        print(f'{BOLD}{CYAN}│{RESET} {BOLD}{WHITE}{fmt_cell(title, max_width - 4)}{RESET} {BOLD}{CYAN}│{RESET}')
        print(f'{BOLD}{CYAN}│{RESET} {DIM}{fmt_cell(sub, max_width - 4)}{RESET} {BOLD}{CYAN}│{RESET}')
        print(f'{BOLD}{CYAN}╰{"─" * (max_width - 2)}╯{RESET}')
        for line in card_table('FLEET HEALTH CHECK', 'rentals, services, temps, memory, power, disks, PCIe, drivers', card_health_columns, card_health_rows):
            print(line)
        for line in card_table('FLEET SECURITY CHECK', 'sudo/users, kernel/driver posture, auditd, AIDE baseline, ports and config drift', card_security_columns, card_security_rows):
            print(line)


    cardtest_gpu_columns = [
        ('Rig', 8), ('Status', 8), ('Flags', 24), ('Cont', 5), ('Driver', 10), ('RAM', 16),
        ('PCIe', 7), ('GPU Temp', 12), ('GPU Junc', 12), ('GPU VRAM', 12),
        ('GPU Power', 18), ('GPU Mem', 22),
    ]
    cardtest_system_columns = [
        ('Rig', 8), ('Vast', 6), ('Docker', 6), ('Host', 12), ('Load', 13),
        ('Disk', 16), ('Uptime', 16), ('Boot', 16), ('Reboot', 7), ('NVMe', 9),
        ('Failed', 6), ('Xid', 10), ('Net', 14), ('Verdict', 24),
    ]

    def summarize_health(rendered_rows):
        total = len(rendered_rows)
        status_counts = {'GOOD': 0, 'WATCH': 0, 'BAD': 0}
        rented = 0
        idle = 0
        for row in rendered_rows:
            status = strip_ansi(str(row.get('Status', ''))).strip().upper()
            if status in status_counts:
                status_counts[status] += 1
            flags = [x.strip().upper() for x in strip_ansi(str(row.get('Flags', ''))).split(',') if x.strip()]
            containers = strip_ansi(str(row.get('Containers', '0'))).strip()
            try:
                cont_n = int(containers)
            except Exception:
                cont_n = 0
            if 'RENTED' in flags or cont_n > 0:
                rented += 1
            else:
                idle += 1
        return total, status_counts, rented, idle

    def summarize_security(rendered_rows):
        counts = {'GOOD': 0, 'WATCH': 0, 'BAD': 0}
        for row in rendered_rows:
            status = strip_ansi(str(row.get('Status', ''))).strip().upper()
            if status in counts:
                counts[status] += 1
        return counts

    def render_dashboard_header(max_width, public, security_rows):
        total, health_counts, rented, idle = summarize_health(rows)
        security_counts = summarize_security(security_rows)
        print()
        print(f'{BOLD}{CYAN}╭{"─" * (max_width - 2)}╮{RESET}')
        title = 'VAST FLEET HEALTH + SECURITY'
        sub = ('anonymized rig1..rigN · ' if public else '') + (
            f'{total} rigs · '
            f'{health_counts["GOOD"]} GOOD · {health_counts["WATCH"]} WATCH · {health_counts["BAD"]} BAD · '
            f'{rented} rented · {idle} idle · '
            f'security {security_counts["GOOD"]} GOOD / {security_counts["WATCH"]} WATCH / {security_counts["BAD"]} BAD'
        )
        print(f'{BOLD}{CYAN}│{RESET} {BOLD}{WHITE}{fmt_cell(title, max_width - 4)}{RESET} {BOLD}{CYAN}│{RESET}')
        print(f'{BOLD}{CYAN}│{RESET} {DIM}{fmt_cell(sub, max_width - 4)}{RESET} {BOLD}{CYAN}│{RESET}')
        print(f'{BOLD}{CYAN}╰{"─" * (max_width - 2)}╯{RESET}')

    def render_cardtest():
        public = bool(args.public_labels)
        gpu_rows = []
        system_rows = []
        for idx, row in enumerate(rows, start=1):
            label = f'rig{idx}' if public else row.get('Rig', f'rig{idx}')
            host = label if public else row.get('Host', '--')
            hint = 'hidden' if public else row.get('Container Hint', '--')
            gpu_rows.append({
                'Rig': label,
                'Status': row.get('Status', '--'),
                'Flags': row.get('Flags', '--'),
                'Cont': row.get('Containers', '--'),
                'Driver': row.get('Driver', '--'),
                'RAM': row.get('RAM', '--'),
                'PCIe': row.get('PCIe', '--'),
                'GPU Temp': row.get('GPU Temp', '--'),
                'GPU Junc': row.get('GPU Junc', '--'),
                'GPU VRAM': row.get('GPU VRAM', '--'),
                'GPU Power': row.get('GPU Power', '--'),
                'GPU Mem': row.get('GPU Mem', '--'),
            })
            system_rows.append({
                'Rig': label,
                'Vast': row.get('Vast', '--'),
                'Docker': row.get('Docker', '--'),
                'Host': host,
                'Load': row.get('Load', '--'),
                'Disk': row.get('Disk', '--'),
                'Uptime': row.get('Uptime', '--'),
                'Boot': row.get('Boot', '--'),
                'Reboot': row.get('Reboot', '--'),
                'NVMe': row.get('NVMe', '--'),
                'Failed': row.get('Failed', '--'),
                'Xid': row.get('Xid', '--'),
                'Net': row.get('Net', '--'),
                'Verdict': row.get('Verdict', '--'),
            })

        security_rows = collect_security_rows()
        for row in security_rows:
            row['Status'] = colorize_status(row['Status'])
            row['Flags'] = colorize_flags(row['Flags'])
            for key in ['UID0', 'Priv Groups', 'API Keys', 'Secrets', 'Keys', 'Ports', 'Kmods', 'Systemd', 'Cron']:
                if row.get(key) not in ('--', 'unknown', ''):
                    row[key] = f'{CYAN}{row[key]}{RESET}'
            if row.get('Auditd') == 'active': row['Auditd'] = f'{GREEN}{row["Auditd"]}{RESET}'
            if row.get('AIDE DB') == 'yes': row['AIDE DB'] = f'{GREEN}{row["AIDE DB"]}{RESET}'
            if row.get('GPU') == 'OK': row['GPU'] = f'{GREEN}{row["GPU"]}{RESET}'
            elif row.get('GPU') == 'UPDATE': row['GPU'] = f'{YELLOW}{row["GPU"]}{RESET}'
            if row.get('CVE') == 'OK': row['CVE'] = f'{GREEN}{row["CVE"]}{RESET}'
            elif 'UPDATE' in str(row.get('CVE')): row['CVE'] = f'{YELLOW}{row["CVE"]}{RESET}'
        card_security_rows = []
        for idx, row in enumerate(security_rows, start=1):
            card_security_rows.append({
                'Rig': f'rig{idx}' if public else row.get('Rig', f'rig{idx}'),
                'Status': row.get('Status','--'),
                'Flags': row.get('Flags','--'),
                'Kernel': row.get('Kernel','--'),
                'CVE': row.get('CVE','--'),
                'Drv': row.get('Drv','--'),
                'GPU': row.get('GPU','--'),
                'Priv Groups': row.get('Priv Groups','--'),
                'Auditd': row.get('Auditd','--'),
                'AIDE': row.get('AIDE DB','--'),
                'API Keys': row.get('API Keys','--'),
                'Secrets': row.get('Secrets','--'),
                'Ports': row.get('Ports','--'),
            })
        expanded_gpu_columns = expand_columns(cardtest_gpu_columns, gpu_rows)
        expanded_system_columns = expand_columns(cardtest_system_columns, system_rows)
        expanded_security_columns = expand_columns(card_security_columns, card_security_rows)
        max_width = max(
            card_width(expanded_gpu_columns),
            card_width(expanded_system_columns),
            card_width(expanded_security_columns),
        )
        render_dashboard_header(max_width, public, security_rows)

        for line in card_table('FLEET HEALTH CHECK 1 — GPU / WORKLOAD', 'rentals, driver/RAM/PCIe, temps, memory and power', cardtest_gpu_columns, gpu_rows):
            print(line)
        for line in card_table('FLEET HEALTH CHECK 2 — SYSTEM / RISK', 'services, load, disk, uptime, reboot, NVMe, Xid, network and verdict', cardtest_system_columns, system_rows):
            print(line)
        for line in card_table('FLEET SECURITY CHECK', 'sudo/users, kernel/driver posture, auditd, AIDE baseline, ports and config drift', card_security_columns, card_security_rows):
            print(line)

    def build_normal_two_line_frame(rendered_rows):
        top_cols = ['Rig', 'Status', 'Flags', 'Host', 'Vast', 'Docker', 'Containers', 'Container Hint', 'GPU Temp', 'GPU Junc', 'GPU VRAM', 'GPU Power']
        bot_cols = ['GPU Mem', 'Driver', 'RAM', 'Boot', 'NTP', 'Net', 'PCIe', 'Reboot', 'NVMe', 'Failed', 'Load', 'Disk', 'Uptime', 'Verdict', 'Xid']
        top_widths = {'Rig': 16, 'Status': 8, 'Flags': 24, 'Host': 18, 'Vast': 6, 'Docker': 6, 'Containers': 5, 'Container Hint': 18, 'GPU Temp': 12, 'GPU Junc': 12, 'GPU VRAM': 12, 'GPU Power': 12}
        bot_widths = {'GPU Mem': 16, 'Driver': 10, 'RAM': 16, 'Boot': 14, 'NTP': 4, 'Net': 12, 'PCIe': 6, 'Reboot': 6, 'NVMe': 10, 'Failed': 6, 'Load': 12, 'Disk': 16, 'Uptime': 16, 'Verdict': 18, 'Xid': 18}
        lines = []
        top_header = ' | '.join(fmt_cell(colorize_header(name), top_widths[name]) for name in top_cols)
        top_values_divider = '-+-'.join('-' * top_widths[name] for name in top_cols)
        bot_header = ' | '.join(fmt_cell(colorize_header(name), bot_widths[name]) for name in bot_cols)
        bot_values_divider = '-+-'.join('-' * bot_widths[name] for name in bot_cols)
        for idx, row in enumerate(rendered_rows):
            host_title = strip_ansi(str(row.get('Host') or row.get('Rig') or '')).strip()
            if host_title:
                lines.append(f'{BOLD}{PURPLE}{host_title}{RESET}')
                lines.append('')
            lines.append(top_header)
            lines.append(f'{DIM}{top_values_divider}{RESET}')
            lines.append(' | '.join(fmt_cell(row[name], top_widths[name]) for name in top_cols))
            lines.append('')
            lines.append('')
            lines.append(bot_header)
            lines.append(f'{DIM}{bot_values_divider}{RESET}')
            lines.append(' | '.join(fmt_cell(row[name], bot_widths[name]) for name in bot_cols))
            if idx != len(rendered_rows) - 1:
                lines.append('')
                lines.append('')
                lines.append('')
        lines.append('')
        lines.append('')
        return lines

    def render_once():
        if args.json:
            plain_rows = []
            for row in rows:
                plain_rows.append({k: strip_ansi(v) if isinstance(v, str) else v for k, v in row.items()})
            print(json.dumps({'rows': plain_rows}, indent=2))
            return

        if args.security:
            security_rows = collect_security_rows()
            for row in security_rows:
                row['Status'] = colorize_status(row['Status'])
                row['Flags'] = colorize_flags(row['Flags'])
                for key in ['UID0', 'Priv Groups', 'API Keys', 'Secrets', 'Keys', 'Ports', 'Kmods', 'Systemd', 'Cron']:
                    if row.get(key) not in ('--', 'unknown', ''):
                        row[key] = f'{CYAN}{row[key]}{RESET}'
            header = ' | '.join(fmt_cell(colorize_header(name), width) for name, width in security_columns)
            divider = '-+-'.join('-' * width for _, width in security_columns)
            print()
            print(f'{BOLD}{PURPLE}━━━━━━━━━━━━━━  FLEET SECURITY CHECK  ━━━━━━━━━━━━━━{RESET}')
            print()
            print(header)
            print(f'{DIM}{divider}{RESET}')
            for row in security_rows:
                print(' | '.join(fmt_cell(row[name], width) for name, width in security_columns))
            return

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

        if args.card:
            render_card()
            return

        render_cardtest()
        return

    def capture_render_once_lines():
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            render_once()
        return buf.getvalue().splitlines()

    def render_watch_screen():
        if sys.stdout.isatty():
            sys.stdout.write('\033[H\033[2J\033[3J')
            sys.stdout.flush()
        render_once()

    wants_watch_view = any([args.cardtest, args.card, args.security, args.flags, args.vertical, args.json])

    if args.telegram_bot is not None:
        try:
            interval = max(10.0, float(args.telegram_bot))
        except Exception:
            interval = 60.0
        print(f'{DIM}telegram-bot active: rental + security alerts every {interval:g}s{RESET}')
        while True:
            results = {}
            with ThreadPoolExecutor(max_workers=len(RIGS) or 1) as ex:
                futs = [ex.submit(run_rig, label, target) for label, target in RIGS]
                for fut in as_completed(futs):
                    label, data = fut.result()
                    results[label] = data
            rows = collect_plain_rows(results)
            maybe_send_rent_transition_alerts(rows)
            rows = apply_health_sheet_stability(rows)
            security_rows = collect_security_rows(results)
            maybe_send_security_alerts(security_rows)
            if wants_watch_view:
                render_watch_screen()
            print(f'{DIM}telegram-bot poll complete; sleeping {interval:g}s{RESET}')
            time.sleep(interval)

    if args.telegram_watch is not None:
        try:
            interval = max(5.0, float(args.telegram_watch))
        except Exception:
            interval = 60.0
        while True:
            results = {}
            with ThreadPoolExecutor(max_workers=len(RIGS) or 1) as ex:
                futs = [ex.submit(run_rig, label, target) for label, target in RIGS]
                for fut in as_completed(futs):
                    label, data = fut.result()
                    results[label] = data
            rows = collect_plain_rows(results)
            maybe_send_rent_transition_alerts(rows)
            rows = apply_health_sheet_stability(rows)
            if wants_watch_view:
                render_watch_screen()
            print(f'{DIM}telegram-watch poll complete; sleeping {interval:g}s{RESET}')
            time.sleep(interval)

    if args.security_telegram_watch is not None:
        try:
            interval = max(10.0, float(args.security_telegram_watch))
        except Exception:
            interval = 60.0
        while True:
            results = {}
            with ThreadPoolExecutor(max_workers=len(RIGS) or 1) as ex:
                futs = [ex.submit(run_rig, label, target) for label, target in RIGS]
                for fut in as_completed(futs):
                    label, data = fut.result()
                    results[label] = data
            rows = apply_health_sheet_stability(collect_plain_rows(results))
            security_rows = collect_security_rows(results)
            maybe_send_security_alerts(security_rows)
            if wants_watch_view:
                render_watch_screen()
            print(f'{DIM}security-telegram-watch poll complete; sleeping {interval:g}s{RESET}')
            time.sleep(interval)

    if not args.watch and not args.watch_v2:
        render_once()
        return

    watch_value = args.watch_v2 if args.watch_v2 is not None else args.watch
    try:
        interval = max(1.0, float(watch_value))
    except Exception:
        interval = 5.0

    # keep the user's chosen view in watch mode; default plain watch stays normal view

    use_watch_v2 = args.watch_v2 is not None

    last_render = None
    first_watch_render = True

    while True:
        if first_watch_render:
            msg = f'collecting fleet data from {len(RIGS)} rigs — first render appears after SSH checks finish…'
            if sys.stdout.isatty():
                sys.stdout.write('\033[H\033[2J\033[3J')
                sys.stdout.flush()
            print(f'{DIM}{msg}{RESET}', flush=True)
            first_watch_render = False

        results = {}
        with ThreadPoolExecutor(max_workers=len(RIGS) or 1) as ex:
            futs = [ex.submit(run_rig, label, target) for label, target in RIGS]
            for fut in as_completed(futs):
                label, data = fut.result()
                results[label] = data
        rows = apply_health_sheet_stability(collect_plain_rows(results))
        if args.ack_nic_events:
            ack_current_nic_events(rows)
            print('Acknowledged current NIC event snapshot for all machines.')
            return
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
            for key in ['Host', 'Containers', 'Container Hint', 'Driver', 'RAM', 'Boot', 'Net', 'PCIe', 'Load', 'Disk']:
                if row.get(key) not in ('--', 'unknown', ''):
                    row[key] = f'{CYAN}{row[key]}{RESET}'
            if row['GPU Temp'] not in ('--', 'unknown', ''):
                row['GPU Temp'] = colorize_temp_metric(strip_ansi(row['GPU Temp']))
            if row['GPU Junc'] not in ('--', 'unknown', ''):
                row['GPU Junc'] = colorize_temp_metric(strip_ansi(row['GPU Junc']), mid=80.0, hot=95.0)
            if row['GPU VRAM'] not in ('--', 'unknown', ''):
                row['GPU VRAM'] = colorize_temp_metric(strip_ansi(row['GPU VRAM']), mid=78.0, hot=90.0)
            if row['GPU Mem'] not in ('--', 'unknown', ''):
                row['GPU Mem'] = colorize_gpu_mem_metric(strip_ansi(row['GPU Mem']))
            if row['GPU Power'] not in ('--', 'unknown', ''):
                row['GPU Power'] = colorize_gpu_power_metric(strip_ansi(row['GPU Power']))
            if row['Uptime'] not in ('--', 'unknown'):
                row['Uptime'] = f'{CYAN}{row["Uptime"]}{RESET}'
        frame_lines = []
        default_dashboard = not any([args.flags, args.vertical, args.security, args.card, args.json])
        if args.cardtest or args.card or args.json or default_dashboard:
            frame_lines = capture_render_once_lines()
        elif args.security:
            security_rows = collect_security_rows(results)
            for row in security_rows:
                row['Status'] = colorize_status(row['Status'])
                row['Flags'] = colorize_flags(row['Flags'])
                for key in ['UID0', 'Priv Groups', 'API Keys', 'Secrets', 'Keys', 'Ports', 'Kmods', 'Systemd', 'Cron']:
                    if row.get(key) not in ('--', 'unknown', ''):
                        row[key] = f'{CYAN}{row[key]}{RESET}'
            header = ' | '.join(fmt_cell(colorize_header(name), width) for name, width in security_columns)
            divider = '-+-'.join('-' * width for _, width in security_columns)
            frame_lines = ['', f'{BOLD}{PURPLE}━━━━━━━━━━━━━━  FLEET SECURITY CHECK  ━━━━━━━━━━━━━━{RESET}', '', header, divider] + [' | '.join(fmt_cell(row[name], width) for name, width in security_columns) for row in security_rows]
        elif args.flags:
            header = ' | '.join(fmt_cell(colorize_header(name), width) for name, width in flag_columns)
            divider = '-+-'.join('-' * width for _, width in flag_columns)
            frame_lines = [header, divider] + [' | '.join(fmt_cell(row[name], width) for name, width in flag_columns) for row in rows]
        elif args.vertical:
            for idx, row in enumerate(rows):
                frame_lines.extend(build_vertical_block(row))
                if idx != len(rows) - 1:
                    frame_lines.append('')
        else:
            frame_lines = build_normal_two_line_frame(rows)

        rendered_snapshot = '\n'.join(strip_ansi(line) for line in frame_lines)
        if use_watch_v2 and rendered_snapshot == last_render:
            time.sleep(interval)
            continue
        last_render = rendered_snapshot

        if sys.stdout.isatty():
            # Always redraw into one clean terminal frame. The old watch-v2 only
            # moved the cursor home, which left ghost boxes behind whenever the
            # card height/width changed or terminal wrapping differed.
            sys.stdout.write('\033[H\033[2J\033[3J')
            sys.stdout.flush()
        if frame_lines and (args.cardtest or args.card or args.json or default_dashboard):
            print('\n'.join(frame_lines))
        else:
            render_once()
        print()
        if use_watch_v2:
            print(f'{DIM}checking every {interval:g}s — redraws only when data changes — Ctrl+C to stop{RESET}')
        else:
            print(f'{DIM}refreshing every {interval:g}s — Ctrl+C to stop{RESET}')
        time.sleep(interval)

if __name__ == '__main__':
    main()
