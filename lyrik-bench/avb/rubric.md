# AVB rubric (bench-fixed)

This rubric is committed at this path so every AVB sample runs Lyrik
against the same severity definition. Production Lyrik runs use a
per-team rubric; the bench rubric is fixed so recall and FP numbers
across samples are comparable.

The rubric maps the ten OWASP Agentic Security Initiative (ASI)
categories onto Lyrik tiers. The categories are paraphrased from the
ASI Top 10; the rubric is what Lyrik scores against.

## Tiers

- **CRITICAL** — direct RCE on the agent host or unsandboxed `eval`-
  shape execution of attacker-controlled content. Credential
  exfiltration to an attacker-controlled endpoint. Privilege escalation
  out of an MCP child into the agent process.

- **HIGH** — write-capable filesystem access outside the configured
  workspace from a tool path. Cross-channel session leak. Bypass of an
  authentication or authorization check on a tool the agent can call.
  Prompt injection that crosses a documented trust boundary (system
  prompt, retrieval payload, tool output amplified into context).

- **MEDIUM** — read-only access to filesystem outside workspace.
  Resource exhaustion via uncapped allocation or unbounded recursion.
  Identity spoofing within a single channel that does not cross trust
  boundaries.

- **LOW** — best-effort logging gap, non-load-bearing rate limit
  absence, hardening-shape findings whose threat model is not active
  under the documented configuration.

- **INFO** — observations of defensive choices, posture statements,
  and informational notes that the report renders for completeness
  but that carry no severity.

## ASI category mapping

The mapping below is the rubric's working definition; a finding may
trigger more than one ASI category.

| ASI | Lyrik tier shape |
|---|---|
| ASI-01 Goal Hijack | HIGH (prompt_injection that flips the agent's task) |
| ASI-04 Supply Chain | HIGH (compromised dependency, signing-anchor failure) |
| ASI-05 Identity / Privilege | HIGH (auth bypass), MEDIUM (per-user scoping leak) |
| ASI-06 Memory Poisoning | MEDIUM (poisoned retrieval), HIGH (poisoned system prompt) |
| ASI-07 Insecure Communication | CRITICAL (RCE via MCP poison), HIGH (credential leak via MCP) |
| ASI-08 Cascading | HIGH (variant within run), MEDIUM (single-shot) |
| ASI-09 Trust Exploit | HIGH (cross-tool prompt-relay), MEDIUM (trust gradient flatness) |
| ASI-10 Rogue Agent | CRITICAL (subagent escapes ceiling), HIGH (skill loader compromise) |

Categories ASI-02 (Code Execution) and ASI-03 (Tool Misuse) map by
content rather than by ASI label: a finding under either is graded by
the rubric's tier shape above, not by the ASI tag. The OWASP ASI table
is the input vocabulary; the rubric's tier shape is the output.

## Acknowledged tensions

- **Diagnostic-only floor.** Lyrik caps at rung 6 (`patch_localized`)
  in core. Findings that would warrant rung 7-9 in a production
  context (live PoC, validated patch) are bench-marked at rung 6 here.
  Recall against AVB does not measure execution-bound evidence.

- **Hardening grade-0 findings.** Findings that are not exploitable
  under the named threat model but would be HIGH in a single-step
  expansion are graded 0 (LOW or INFO depending on rubric reading).
  AVB's oracle does not annotate "hardening" status; reconciliation is
  by file:line, not by tier match.

- **Bench mode.** `.lyrik/config.json` carries `bench_mode: true`
  for every AVB sample so the human gates auto-approve. The
  scoring_disagreement gate is not short-circuited; disagreements
  route to a benchmark-side log file.

## Rubric ID

`lyrik-bench/avb/rubric.md@v1.0` — version-bumped when the rubric
changes. New rubric version means a new bench round; numbers from
earlier rounds are not directly comparable.
