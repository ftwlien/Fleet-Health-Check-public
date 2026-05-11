# Security Policy

## Supported versions

Security fixes are applied to the latest `main` branch.

## Reporting a vulnerability

Please report security issues privately to the repository owner instead of opening a public issue with exploit details.

## Important security notes

- Fleet Health Check is designed to collect read-only health information from machines you control over SSH.
- Keep SSH private keys, host inventories, usernames, hostnames, public IPs, and internal network details out of public issues, screenshots, and commits unless you intentionally want them public.
- The example rig list uses private placeholder LAN addresses. Replace those locally; do not commit your real fleet inventory.
- Telegram alerts use `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` from environment variables. Never commit real bot tokens or chat IDs.
- The prerequisite installer may add limited passwordless sudo rules for tools such as `smartctl` and `gputemps` so health checks can run non-interactively. Review those rules before installing on production machines.
- The optional security stack configures `auditd` and `aide` for drift detection. Test it on one rig before rolling it out fleet-wide.
- Do not paste private keys, Vast.ai API keys, Telegram bot tokens, cloud credentials, or full fleet host lists into GitHub issues.
- If you fork or modify this project, avoid committing generated state files, local reports, credentials, SSH material, logs, or machine-specific config.
