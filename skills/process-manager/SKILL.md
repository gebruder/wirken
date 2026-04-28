---
name: process-manager
description: Monitor and manage system processes
permissions:
  tools:
    allow: [exec]
  egress:
    mode: deny
  inference:
    allow: ["*"]
---

# Process Manager

Monitor and manage system processes.

## List processes

- All: `ps aux`
- By CPU: `ps aux --sort=-%cpu | head -15`
- By memory: `ps aux --sort=-%mem | head -15`
- By name: `pgrep -af "<name>"`
- Tree: `pstree -p | head -40`

## Manage processes

- Kill by PID: `kill <pid>`
- Force kill: `kill -9 <pid>`
- Kill by name: `pkill <name>`
- Kill by port: `fuser -k <port>/tcp`

## Monitor

- Find by port: `ss -tlnp | grep <port>`
- Open files: `lsof -p <pid> | head -20`
- File descriptors: `ls /proc/<pid>/fd | wc -l`
- Watch in real-time: `top -bn1 | head -20`

## Services (systemd)

- Status: `systemctl status <service>`
- Start/stop: `systemctl start|stop|restart <service>`
- Logs: `journalctl -u <service> --no-pager -n 30`
- List running: `systemctl list-units --type=service --state=running`
