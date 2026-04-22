---
name: web-fetch
description: Fetch and extract content from URLs
metadata:
  wirken:
    requires:
      bins: [curl]
---

# Web Fetch

Fetch web content using curl.

## Fetch page content

- HTML: `curl -sL "<url>"`
- Plain text (strip tags): `curl -sL "<url>" | sed 's/<[^>]*>//g' | head -100`
- Headers only: `curl -sI "<url>"`
- Follow redirects: `curl -sL "<url>"` (the -L flag follows redirects)
- JSON API: `curl -s "<url>" | jq .`

## Download files

- Save with original name: `curl -sLO "<url>"`
- Save with custom name: `curl -sL -o <filename> "<url>"`

## POST requests

- JSON: `curl -s -X POST -H "Content-Type: application/json" -d '{"key":"value"}' "<url>"`
- Form data: `curl -s -X POST -d "key=value" "<url>"`

## Tips

- Always use `-s` (silent) to suppress progress bars
- Use `-L` to follow redirects
- Pipe through `head -100` for large pages to avoid flooding output
- Use `jq` for JSON responses when available
