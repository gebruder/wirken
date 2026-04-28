---
name: weather
description: Get current weather and forecasts
disable-model-invocation: false
metadata:
  wirken:
    requires:
      bins: [curl]
permissions:
  tools:
    allow: [exec]
  egress:
    mode: deny
  inference:
    allow: ["*"]
---

# Weather

Get weather information using wttr.in.

## Usage

- Current weather: `curl -s "wttr.in/CityName?format=3"`
- Detailed forecast: `curl -s "wttr.in/CityName"`
- One-line summary: `curl -s "wttr.in/CityName?format=%l:+%c+%t+%w+%h"`
- Moon phase: `curl -s "wttr.in/Moon"`

Replace spaces in city names with `+` (e.g., `New+York`).

For JSON output: `curl -s "wttr.in/CityName?format=j1"`
