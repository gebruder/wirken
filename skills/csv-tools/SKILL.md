---
name: csv-tools
description: Parse and analyze CSV data
disable-model-invocation: false
permissions:
  tools:
    allow: [exec]
  egress:
    mode: deny
  inference:
    allow: ["*"]
---

# CSV Tools

Work with CSV files using standard shell tools.

## View

- First few rows: `head -5 data.csv`
- Column headers: `head -1 data.csv`
- Row count: `wc -l data.csv`
- Specific columns (1st and 3rd): `cut -d',' -f1,3 data.csv`

## Filter and sort

- Filter rows: `awk -F',' '$3 > 100' data.csv`
- Sort by column: `sort -t',' -k2 -n data.csv`
- Unique values in column: `cut -d',' -f2 data.csv | sort -u`
- Count by value: `cut -d',' -f2 data.csv | sort | uniq -c | sort -rn`

## Transform

- Remove header: `tail -n +2 data.csv`
- Add line numbers: `nl -ba data.csv`
- Replace delimiter: `sed 's/,/\t/g' data.csv` (CSV to TSV)

## Python (for complex operations)

```
python3 -c "
import csv, sys
reader = csv.DictReader(open('data.csv'))
for row in reader:
    print(row)
" | head -10
```
