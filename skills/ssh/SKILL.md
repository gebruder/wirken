---
name: ssh
description: SSH key management and remote connections
metadata:
  openclaw:
    requires:
      bins: [ssh]
---

# SSH

Manage SSH keys and connections.

## Key management

- List keys: `ls -la ~/.ssh/`
- Generate key: `ssh-keygen -t ed25519 -C "comment"`
- Show public key: `cat ~/.ssh/id_ed25519.pub`
- Test connection: `ssh -T git@github.com`

## Config

- View: `cat ~/.ssh/config`
- List known hosts: `cat ~/.ssh/known_hosts | wc -l`

## Remote operations

- Connect: `ssh user@host`
- Run command: `ssh user@host "command"`
- Copy file to remote: `scp file.txt user@host:/path/`
- Copy from remote: `scp user@host:/path/file.txt .`
- Port forward: `ssh -L 8080:localhost:80 user@host`

## Tips

- Use `ssh-add` to add keys to the agent
- Check `ssh -v user@host` for connection debugging
