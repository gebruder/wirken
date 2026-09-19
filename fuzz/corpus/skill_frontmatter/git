---
name: git
description: Git version control operations
disable-model-invocation: true
metadata:
  wirken:
    requires:
      bins: [git]
permissions:
  tools:
    allow: [exec]
  egress:
    mode: deny
  inference:
    allow: ["*"]
---

# Git

Perform git operations in the workspace.

## Common operations

- Status: `git status`
- Log: `git log --oneline -20`
- Diff: `git diff`
- Staged diff: `git diff --cached`
- Add files: `git add <file>` or `git add -A`
- Commit: `git commit -m "message"`
- Branch: `git branch -a`
- Switch branch: `git checkout <branch>` or `git switch <branch>`
- Create branch: `git checkout -b <branch>`
- Pull: `git pull`
- Push: `git push`
- Stash: `git stash` / `git stash pop`
- Blame: `git blame <file>`
- Search history: `git log --grep="pattern"`
- Find who changed a line: `git log -p -S "text" -- <file>`

## Tips

- Always check `git status` before committing
- Use `git diff --stat` for a summary of changes
- Use `git log --oneline --graph` for branch visualization
