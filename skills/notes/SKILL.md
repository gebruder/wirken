---
name: notes
description: Create and manage text notes in the workspace
permissions:
  tools:
    allow: [exec, read_file, write_file, list_files]
  egress:
    mode: deny
  filesystem:
    read_paths: ["<workspace>"]
    write_paths: ["<workspace>"]
  inference:
    allow: ["*"]
---

# Notes

Manage text notes stored as files in the workspace.

## Creating notes

Save notes as markdown files in a `notes/` directory within the workspace.

- Create a note: write to `notes/<topic>.md`
- Use ISO dates for time-sensitive notes: `notes/2024-01-15-meeting.md`
- Use descriptive names: `notes/project-ideas.md`

## Finding notes

- List all notes: `ls notes/`
- Search notes: `grep -r "keyword" notes/`
- Recent notes: `ls -lt notes/ | head -10`

## Conventions

- One topic per file
- Use markdown headings for structure
- Append to existing notes with a date header rather than overwriting
- Example append format:

```
## 2024-01-15

New content here.
```
