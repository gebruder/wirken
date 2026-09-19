---
name: system-info
description: System information and monitoring
disable-model-invocation: false
permissions:
  tools:
    allow: [exec]
  egress:
    mode: deny
  inference:
    allow: ["*"]
---

# System Info

Gather system information and monitor resources.

## Hardware and OS

- OS info: `uname -a`
- CPU: `nproc` (count), `lscpu | head -20` (details)
- Memory: `free -h`
- Disk: `df -h`
- Uptime: `uptime`
- Hostname: `hostname`

## Processes

- Top processes by CPU: `ps aux --sort=-%cpu | head -15`
- Top processes by memory: `ps aux --sort=-%mem | head -15`
- Process tree: `pstree -p | head -30`
- Find process: `pgrep -a <name>`

## Network

- IP addresses: `ip addr show` or `hostname -I`
- Open ports: `ss -tlnp`
- DNS: `cat /etc/resolv.conf`
- Test connectivity: `ping -c 3 <host>`

## Logs

- System log (recent): `journalctl --no-pager -n 30`
- Kernel messages: `dmesg | tail -20`
