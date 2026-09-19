---
name: file-search
description: Find files and search content across directories
disable-model-invocation: false
permissions:
  tools:
    allow: [exec]
  egress:
    mode: deny
  inference:
    allow: ["*"]
---

# File Search

Find files and search content across directories.

## Find files by name

- By name: `find . -name "*.py" -type f`
- Case-insensitive: `find . -iname "*.txt" -type f`
- Modified recently: `find . -name "*.rs" -mtime -1 -type f`
- Large files: `find . -size +10M -type f`

## Search file contents

- Grep: `grep -rn "pattern" .`
- Case-insensitive: `grep -rni "pattern" .`
- With context: `grep -rn -C 3 "pattern" .`
- File type filter: `grep -rn --include="*.py" "pattern" .`
- Ripgrep (faster): `rg "pattern"` or `rg -t py "pattern"`

## Directory overview

- Tree (if available): `tree -L 2`
- Size summary: `du -sh */ | sort -rh | head -20`
- File count by extension: `find . -type f | sed 's/.*\.//' | sort | uniq -c | sort -rn | head -15`
- Recently modified: `find . -type f -mtime -1 | head -20`
