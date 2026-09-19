---
name: json-tools
description: Parse, query, and transform JSON data
disable-model-invocation: false
metadata:
  wirken:
    requires:
      bins: [jq]
permissions:
  tools:
    allow: [exec]
  egress:
    mode: deny
  inference:
    allow: ["*"]
---

# JSON Tools

Parse and transform JSON using jq.

## Query

- Pretty print: `echo '<json>' | jq .`
- Get field: `echo '<json>' | jq '.field'`
- Nested field: `echo '<json>' | jq '.a.b.c'`
- Array element: `echo '<json>' | jq '.[0]'`
- Array length: `echo '<json>' | jq 'length'`

## Filter and transform

- Select fields: `echo '<json>' | jq '{name: .name, id: .id}'`
- Filter array: `echo '<json>' | jq '.[] | select(.status == "active")'`
- Map: `echo '<json>' | jq '[.[] | .name]'`
- Sort: `echo '<json>' | jq 'sort_by(.date)'`
- Group: `echo '<json>' | jq 'group_by(.type)'`
- Unique: `echo '<json>' | jq '[.[].category] | unique'`

## File operations

- Read and query: `jq '.key' file.json`
- Compact: `jq -c . file.json`
- Raw strings (no quotes): `jq -r '.name' file.json`
- Convert to CSV: `jq -r '.[] | [.name, .value] | @csv' file.json`
