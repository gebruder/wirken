# Authoring a Lyrik scoring guide

This page is for security teams about to run Lyrik for the first time on their codebase. It tells you what a Lyrik scoring guide is, how it gets written (mostly by Lyrik in collaboration with you, not by you from scratch), what sections to include, and what good rubric content looks like.

For what Lyrik is and why it exists, see [lyrik-overview.md](lyrik-overview.md). For setup and configuration, see [lyrik.md](lyrik.md).

## What a Lyrik scoring guide is

A markdown file at `.lyrik/rubric.md` in the repository being assessed. Lyrik scores every finding against this guide. The team owns it, commits it, and reviews it in PR like any other artifact.

A Lyrik scoring guide is not:

- **CVSS-shaped.** CVSS produces a number; a Lyrik rubric produces tier definitions specific to the software being assessed.
- **A compliance checklist.** Lyrik is not a compliance tool. The rubric does not enumerate MITRE ATLAS techniques or OWASP Top 10 items unless the team consciously chooses to anchor against them.
- **Universal.** Different projects need different rubrics. The same project needs a different rubric when its threat model changes.

## When you write it

Usually you don't write the first version from scratch. Lyrik's Phase 0 generates a draft from the project context (language, framework, entry points, trust boundaries, data flows, auth model, network surface), routes it to the `phase_0_signoff` gate, and waits for the team to review and amend.

What the team does at sign-off:

1. Read the generated draft.
2. Reject incorrect tier assignments. Lyrik is calibrating against your software's threat model; if it gets the threat model wrong, the rubric is wrong.
3. Add what's missing. Lyrik's draft will sometimes miss a security property the team considers load-bearing (a specific data-confidentiality requirement, a per-tenant isolation invariant) or a non-property the team explicitly excludes (availability of a specific subsystem).
4. Approve or amend. The approved version writes to `.lyrik/rubric.md` and commits.

You can pre-author a rubric if you have strong opinions about your project's threat model. Lyrik reads a pre-existing `.lyrik/rubric.md` and skips Phase 0's rubric-generation step, going straight to sign-off review. Most teams find letting Phase 0 produce the draft is faster than starting from a blank page; the draft becomes the strawman to amend.

## What sections to include

The structural shape that has worked for real assessments. Use these seven sections as a template.

### 1. Software identification

A one-line header naming the project and scope. *"Severity rubric — FreeBSD RPCSEC_GSS kernel module"* tells a future reader what this rubric is for. Phase 0 fills this in from project context.

### 2. What is a security property of *this* software

A bulleted list. Each item names something the software is responsible for protecting, with a one-clause definition of what compromise looks like.

The list is project-specific. A kernel module's list looks different from a web application's, which looks different from a CLI tool's. Compliance scanners cannot write this list because the answer depends on what *this* software is for.

Shape:

```
- **Integrity of the kernel address space** under network input.
- **Confidentiality and integrity of data** the operator chose to route through Kerberized NFS.
- **Replay protection** for authenticated RPCs.
- **Per-vnet isolation** of RPCSEC_GSS state.
- **Authentication soundness in time** — the GSS verifier must run before any privileged operation on credential bytes.
```

Each entry is a security property + the threat model under which it is a security property. Brief is good.

### 3. What is *not* a security property

A bulleted list of failure modes the rubric does not count as security findings. This list is the rubric's most opinionated section.

Common entries:

- *Availability of the software itself*, when crashing it is purely operational impact and not exploitable.
- *Code style, comment polish, naming.*
- *Dead-code findings that no caller reaches in any built configuration.*

The negative list matters because it tells Lyrik what *not* to escalate. Without it, every panic looks like a HIGH-severity DoS, every unsafe-call-pattern looks like a vulnerability, and the report fills with noise the team has to manually discard every run.

### 4. Tiers

CRITICAL / HIGH / MEDIUM / LOW / INFO, each defined for *this* software. The definitions are not generic.

Shape:

```
#### CRITICAL

Pre-auth remote code execution in kernel context. Pre-auth out-of-bounds write
of attacker-controlled bytes in kernel context. Disclosed key material to a
network attacker. Authentication bypass that lets an unauthenticated peer
present as a previously-authenticated client.

CVE-2026-4747 is the type specimen.
```

A CRITICAL on a kernel module looks different from a CRITICAL on a web service or a CLI tool. Write the definition that matches *this* threat model.

Most rubrics name a **type specimen** per tier — a known finding (a CVE, an internal disclosure) that is the canonical example of that tier. The type specimen anchors the scorer; without one, tier definitions drift run to run.

### 5. Acknowledged tensions

A bulleted list of project-level constraints the rubric consciously accepts. These are the cases where Lyrik would otherwise produce findings the team would discard every run.

Examples:

- *"The kernel module trusts userspace gssd. A gssd compromise compromises this module. This is by design — the kernel does not run Kerberos directly."*
- *"The chacha20poly1305 dependency is at 0.x because RustCrypto has no 1.0 release; the rubric accepts this rather than flagging it."*
- *"Availability is not a security property of this development tool; crashes that do not corrupt memory are not findings."*

The acknowledged-tensions section keeps successive runs from re-litigating the same trade-offs. Lyrik renders findings of these shapes as INFO with a pointer to the acknowledged tension, instead of re-discovering them as MEDIUM-or-higher every run.

### 6. Rubric-silent cases

A short paragraph explaining what Lyrik does when a finding does not cleanly tier under the rubric. Lyrik routes such findings to the `scoring_disagreement` gate with a `rubric_clarification` tag rather than inventing a tier; the team refines the rubric in-flight.

This section exists so the team knows the workflow for cases the rubric does not yet cover. Most teams copy the same paragraph into every rubric.

### 7. Run-specific constraints

A bulleted list of constraints that apply to the current run shape but are not permanent rubric content. Examples: kernel runtime out of scope for the exploit-attempt phase; channel adapters simulated; audit log location.

The canonical home for this content is a separate file at `.lyrik/run-constraints.md`, with the rubric mirroring it under this heading and a `Per .lyrik/run-constraints.md:` pointer. The split lets the rubric stay stable across runs while the constraints file changes per engagement. The articulate phase consumes the constraints file directly; the rubric mirror is for the human reader.

This section is the place where the team discloses *what this run did and didn't exercise*, so the report's funnel can name those categories explicitly (e.g. `stopped_at_0.5_kernel_runtime_oos` as a named line item, not a footnote). Distinct from the acknowledged-tensions section because constraints are about *this run*; tensions are about *the project*.

## Form

Markdown. Whatever renders well in the team's review channel. Tables for tier definitions, prose for narrative sections, bulleted lists for examples. Committed to `.lyrik/rubric.md` and reviewed in PR like any other artifact.

The form does not need to match what other teams use. It needs to be readable to *this* team, in the channel where Phase 0 sign-offs land.

## Refining over time

The rubric is not write-once. Three triggers for refinement:

- **Lyrik routes a finding to `scoring_disagreement` with `rubric_clarification` tag.** The rubric was silent on this class. Add the class. Re-score the routed finding against the refined rubric.
- **Threat model shifts.** A deployment change, a new attacker capability, a new compliance posture the team adopts. The rubric refines deliberately, not reactively.
- **Project changes substantially.** Major refactor, new subsystem, new trust boundary. Phase 0 invalidates and regenerates the project context; the rubric usually needs corresponding updates.

Each refinement commits to git like any code change. PR review is where the team decides whether the refinement is correct.

## What not to put in

- **Generic compliance frameworks.** MITRE ATLAS, OWASP Top 10, NIST AI RMF, and similar are not Lyrik rubric content unless the team consciously anchors against them. A rubric that reads as a compliance checklist tells the operator little about *this* software's threat model.
- **CVSS-style numerical scoring.** Lyrik produces tier–grade–stream output, not a number. A rubric that tries to compute a CVSS-equivalent is fighting the tool's design.
- **Editorial commentary.** *"This code is bad"* is not a rubric tier. *"Pre-auth out-of-bounds write of attacker-controlled bytes in kernel context"* is.
- **Catch-all clauses.** *"Anything else the team considers severe"* is not a tier definition. If the team considers it severe, write the class definition.

## See also

- [`lyrik-overview.md`](lyrik-overview.md) — what Lyrik is, who it is for, what it refuses to do.
- [`lyrik.md`](lyrik.md) — setup, configuration, the `phase_0_signoff` gate where rubric review happens.
- `skills/lyrik/SKILL.md` — the skill itself, including the `## Phase 0 — project context and rubric` section's view of what Lyrik produces and routes.
