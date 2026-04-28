---
name: disk-usage
description: Analyze disk usage and find large files
permissions:
  tools:
    allow: [exec]
  egress:
    mode: deny
  inference:
    allow: ["*"]
---

# Disk Usage

Analyze disk space and find what's taking up room.

## Overview

- Filesystem usage: `df -h`
- Current directory: `du -sh .`
- Subdirectory sizes: `du -sh */ | sort -rh`
- Top 20 largest dirs: `du -h --max-depth=2 | sort -rh | head -20`

## Find large files

- Top 20 largest files: `find . -type f -exec du -h {} + | sort -rh | head -20`
- Files over 100MB: `find . -size +100M -type f -exec ls -lh {} \;`
- Files over 1GB: `find . -size +1G -type f -exec ls -lh {} \;`

## Cleanup candidates

- Old log files: `find /var/log -name "*.gz" -mtime +30 -type f`
- Core dumps: `find / -name "core.*" -type f 2>/dev/null`
- Docker: `docker system df` (if Docker is installed)
- Package cache (apt): `du -sh /var/cache/apt/archives/`
