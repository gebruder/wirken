---
name: tmux
description: Manage tmux terminal sessions
metadata:
  openclaw:
    requires:
      bins: [tmux]
---

# Tmux

Manage tmux sessions, windows, and panes.

## Sessions

- List: `tmux ls`
- New: `tmux new-session -d -s <name>`
- Kill: `tmux kill-session -t <name>`
- Send command: `tmux send-keys -t <session> '<command>' Enter`
- Capture output: `tmux capture-pane -t <session> -p`

## Windows and panes

- New window: `tmux new-window -t <session>`
- Split horizontal: `tmux split-window -h -t <session>`
- Split vertical: `tmux split-window -v -t <session>`
- List windows: `tmux list-windows -t <session>`

## Tips

- Use `tmux send-keys` + `tmux capture-pane` to run commands and read output in background sessions
- Always check `tmux ls` before creating new sessions
