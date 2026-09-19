---
name: calculator
description: Math calculations and unit conversions
disable-model-invocation: false
permissions:
  tools:
    allow: [exec]
  egress:
    mode: deny
  inference:
    allow: ["*"]
---

# Calculator

Perform calculations using shell tools.

## Arithmetic

- Basic math: `echo "scale=4; 355/113" | bc -l`
- Percentages: `echo "scale=2; 847 * 0.15" | bc -l`
- Powers: `echo "2^32" | bc`
- Square root: `echo "scale=4; sqrt(2)" | bc -l`

## Python (if available)

For complex math: `python3 -c "import math; print(math.log2(1024))"`

## Unit conversions

- Bytes to human: `numfmt --to=iec 1073741824` (gives 1.0G)
- Human to bytes: `numfmt --from=iec 4G` (gives 4294967296)
- Temperature: `python3 -c "c=37; print(f'{c}C = {c*9/5+32}F')"`

## Date math

- Days between dates: `echo $(( ($(date -d 2025-12-31 +%s) - $(date +%s)) / 86400 )) days`
- Date in N days: `date -d "+30 days" +%Y-%m-%d`
- Timestamp to date: `date -d @1700000000`
