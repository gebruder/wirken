---
name: github
description: GitHub operations via the gh CLI
metadata:
  wirken:
    requires:
      bins: [gh]
---

# GitHub

Use the `gh` CLI for GitHub operations. The user must be authenticated (`gh auth login`).

## Common operations

- List repos: `gh repo list`
- View repo: `gh repo view owner/repo`
- List issues: `gh issue list -R owner/repo`
- Create issue: `gh issue create -R owner/repo --title "Title" --body "Body"`
- List PRs: `gh pr list -R owner/repo`
- View PR: `gh pr view 123 -R owner/repo`
- Create PR: `gh pr create --title "Title" --body "Body"`
- Check CI status: `gh run list -R owner/repo --limit 5`
- View run logs: `gh run view <run-id> --log-failed`
- Star a repo: `gh repo star owner/repo`
- Clone: `gh repo clone owner/repo`
- Search code: `gh search code "pattern" -R owner/repo`
- Search issues: `gh search issues "query" -R owner/repo`

## Tips

- Use `--json` flag for machine-readable output: `gh issue list --json number,title,state`
- Use `--jq` for filtering: `gh pr list --json title,url --jq '.[].url'`
- Most commands accept `-R owner/repo` to target a specific repository
