# Brocard rejections in Lyrik

The seven rules below are William Woodruff's list at [vulnbrocards.com](https://vulnbrocards.com/). This page restates them in this repo's words and links each rule's source page.

Lyrik records every candidate it declines with the rule that applied and a one-line reason. A declined candidate is never dropped silently.

## The seven rules

Rule numbers match the source list: rule N is VB00N.

1. **No threat model.** A finding states an attacker capability and a harm path. Without both it is not a finding, it is an observation. Source: [VB001](https://vulnbrocards.com/brocards/vb001-no-vuln-report-without-threat-model/). The runner checks this structurally, before the citation gate.
2. **Precondition at least as strong as impact.** If the attacker precondition already grants the impact (the attacker holds the access the harm needs), the finding is not an exploit. Source: [VB002](https://vulnbrocards.com/brocards/vb002-no-exploit-from-heavens/). Judged by the walks, which compare `attacker_capability` with the impact.
3. **No vulnerability outside usage.** A sink reached only through callers that bound the input is not a finding. A precondition violation belongs to the caller, not the API. An upstream advisory whose vulnerable surface is unreachable here is not a re-finding. Source: [VB003](https://vulnbrocards.com/brocards/vb003-no-vuln-outside-of-usage/). Judged by the graph and invariant walks.
4. **No vulnerability from standard behavior.** Behavior the relevant specification permits is not a finding. An implementation stricter than its spec that fails its own strictness still is. Source: [VB004](https://vulnbrocards.com/brocards/vb004-no-vuln-from-standard-behavior/). Judged by the crypto and sink walks.
5. **No vulnerability from documented behavior.** Behavior the project documents, including its security implications, is not a finding. The finding moves to any downstream usage that ignores the documentation, or is dropped. Source: [VB005](https://vulnbrocards.com/brocards/vb005-no-vuln-from-documented-behavior/). Judged by the doc walk.
6. **No cure worse than the disease.** Severity weighs remediation cost against impact. A ReDoS in a context the caller can cancel locally is the reference case. Source: [VB006](https://vulnbrocards.com/brocards/vb006-no-cure-worse-than-disease/). Judged by every walk.
7. **The report is neither necessary nor sufficient.** A Semgrep seed records provenance and earns no credit for existing. A seed is not evidence in either direction. Source: [VB007](https://vulnbrocards.com/brocards/vb007-report-neither-necessary-nor-sufficient/). Structural: nothing in the gate reads a seed's `detection_source`, so a seed changes no decision. A seed whose only candidates were removed is counted as `brocard_rejected` in the scanner funnel.

Rules 1 and 7 are structural and run in the gate. Rules 2 to 6 are judgment. Each walk applies the rules listed in its own section of the staged skill.

## Modes

The `mode` key in `.lyrik/config.json` chooses what a rejection does to the finding. It defaults to `"pentest"`. Any other value fails the run before any walk runs.

- **`pentest`** keeps the finding in `findings.json` and halves its grade once per distinct rule that applied. Two rules halve it twice. There is no floor, and a positive grade never reaches zero. A finding with no numeric grade is kept unchanged.
- **`defender`** removes the finding from `findings.json`. The rejection record stays. The funnel counts removed candidates as `brocard_removed`.

Both modes write every rejection to `rejected_candidates`, and both print the run summary.

## The `rejected_candidates` record

`findings.json` carries a top-level `rejected_candidates` array, one entry per applied rule. A candidate that breaks two rules has two entries.

| Field | Meaning |
|---|---|
| `rule` | Brocard rule number, 1 to 7 |
| `reason` | One line: why the rule applies |
| `applied_by` | `brocard_structural` for the gate, or `walk:<name>` for a walk's judgment |
| `walk` | The walk that emitted the candidate. Absent in single-call mode |
| `stable_id` | The finding's stable ID, when it has one |
| `title` | The finding's title, when it has one |
| `location` | `{file, line_start}` of the finding, when it has one |

Fields the runner cannot fill are omitted rather than set to null.

The array sits outside the findings schema's contract. The validator accepts it, and a later release may change it. See [lyrik.md](lyrik.md#carried-outside-schema-11).

## SARIF

`wirken lyrik report --format sarif` writes each rejection as a result after the kept findings:

- `ruleId` is `lyrik.brocard.<rule>`. Rules `lyrik.brocard.1` to `lyrik.brocard.7` are in the driver's rule list.
- `level` is `note`.
- `message` is the reason, prefixed by the title when there is one.
- `suppressions` is `[{"kind": "external", "justification": "<reason>"}]`. A SARIF consumer shows the result as suppressed, with the reason as its justification.
- `properties.lyrik.rejection` carries `rule`, `walk`, `stable_id`, and `applied_by`.

## `rejections.jsonl`

Each run writes `rejections.jsonl` in the run directory, beside `findings.json`. It is written with `findings.json`. It has one JSON object per line. Each object is a `rejected_candidates` entry with one more field, `"label": "negative"`. The file is empty when nothing was rejected. It is the calibration corpus's negative-label form; nothing in this repo reads it yet.

## Run summary

When a run ends, Lyrik prints the rejections grouped by rule next to the kept count. The summary is computed from the `rejected_candidates` and `findings` arrays of the written `findings.json`, so the printed numbers and the file agree.

With no rejections, one line says so:

```
brocard rejections: none (4 findings kept)
```

With rejections, the first line gives the total and the kept count. Each rule that fired gets a line:

```
brocard rejections: 2 (1 findings kept)
  rule 1 (No threat model): 1
  rule 5 (No vulnerability from documented behavior): 1
```

## What a walk must emit

Every finding carries a `threat_model` object with two non-blank strings:

```json
"threat_model": {
  "attacker_capability": "<what the attacker must already be able to do>",
  "harm_path": "<how that capability reaches the harm>"
}
```

A finding missing either string is a rule 1 rejection. If the attacker capability already grants the impact, the finding is not an exploit, and the walk should not stage it.

A walk that judges a candidate under rules 2 to 6 still writes the finding. It also writes a rejection file, `staging/<walk>/rejections/rejection-NNN.json`, with the rule number, the finding's `stable_id`, and a one-sentence reason:

```json
{"rule": 5, "stable_id": "auth::src/a.rs:10", "reason": "documented as intended"}
```

A rejection file that does not parse, or names a rule outside 1 to 7, is refused. The run records it as `lyrik.brocard.refused` in the audit log.

Single-call mode reads the bundled `lyrik` skill. Until a signed release ships that skill's `threat_model` instruction, its findings carry no `threat_model` and receive rule 1 rejections.

## Worked example

This example is the output of the test `pentest_halves_once_per_distinct_rule_and_keeps_the_finding` in `crates/cli/src/commands/lyrik.rs`. The fixture is a `sink-walk` finding at `src/a.rs:10`, `auth`, grade 0.5, with no `threat_model`. The walk also wrote a rule 5 rejection for the same `stable_id`. The run is in `pentest` mode.

The `rejected_candidates` array in `findings.json`:

```json
"rejected_candidates": [
  {
    "applied_by": "brocard_structural",
    "location": { "file": "src/a.rs", "line_start": 10 },
    "reason": "threat_model lacks attacker_capability and harm_path",
    "rule": 1,
    "stable_id": "auth::src/a.rs:10",
    "title": "stub",
    "walk": "sink-walk"
  },
  {
    "applied_by": "walk:sink-walk",
    "location": { "file": "src/a.rs", "line_start": 10 },
    "reason": "documented as intended",
    "rule": 5,
    "stable_id": "auth::src/a.rs:10",
    "title": "stub",
    "walk": "sink-walk"
  }
]
```

The kept finding, with `citation_check` left out. Its grade went from 0.5 to 0.125, halved once for each of the two distinct rules:

```json
{
  "dedup_sources": ["sink-walk"],
  "detection_source": "model_reasoning",
  "framing": ["auth"],
  "grade": 0.125,
  "id": "F001",
  "location": { "file": "src/a.rs", "line_start": 10 },
  "stable_id": "auth::src/a.rs:10",
  "summary": "stub",
  "tier": "HIGH",
  "title": "stub"
}
```

The run summary printed at the end of the run:

```
brocard rejections: 2 (1 findings kept)
  rule 1 (No threat model): 1
  rule 5 (No vulnerability from documented behavior): 1
```

In `defender` mode the same fixture removes the finding from `findings.json`. The two `rejected_candidates` entries stay, and the run summary prints:

```
brocard rejections: 2 (0 findings kept)
  rule 1 (No threat model): 1
  rule 5 (No vulnerability from documented behavior): 1
```
