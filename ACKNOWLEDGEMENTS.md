# Acknowledgements

People outside the project who found a defect, reported one, proposed a
feature or supplied a design that Wirken shipped. Each line is taken from the
[CHANGELOG](CHANGELOG.md) entry of the release it names.

This is not a list of code authors. Who wrote a commit is in the git history.
A person is listed here for what they did, in the changelog's own word:
found, reported, proposed, designed.

## Matthew Busel (@Mattbusel)

- 3.4.1: found that Anthropic's Opus 4.5 and Opus 4.7 were priced at $15
  input and $75 output per million tokens where the list price is $5 and $25.
- 3.4.1: reported that the current Anthropic, OpenAI and Gemini models had
  no row in the pricing table (#313).
- 3.4.1: reported that Opus 5.5 reads its cache at 0.05 times input, not
  0.1 times (#313).

## Tanmay Maka (@maka-tanmay)

- Unreleased: proposed plan sign-in, which a Lyrik run can now use.
- 3.0.0: found that a turn hitting a ChatGPT plan's usage limit did not reply
  with the limit notice and the Manage usage link.
- 2.5.0: designed the light Markdown rendering of `wirken chat` replies
  (#300).
- 2.5.0: designed the `wirken chat` slash commands (#301).
- 2.5.0: designed `wirken sessions verify --with-children` (#302).
- 2.5.0: found that a message naming a skill that is not loaded got the
  internal-error apology instead of the loaded skills.
- 2.5.0: found that a `plan_sign_in` kind or a `(plan)` model label pushed
  the columns of `wirken credentials list` and `wirken agents list` out of
  line.
- 2.5.0: found, with the reproduction on a 2.4.0 chain, that
  `wirken sessions verify` reported a `messages_hash` divergence on every
  `wirken ask` after the first.
- 2.5.0: found, with its wider scope, that in 1.20.0 through 2.3.0 any
  sub-agent spawned on a non-streaming turn was left unbound.
- 2.4.0: proposed `wirken chat`.
- 2.4.0: proposed plan sign-in for the `openai` provider.
- 2.4.0: found that sub-agents started by several `spawn_subagent` calls in
  one turn did not write their `SubagentSessionBound` row.
- 2.4.0: found that spawning a sub-agent logged "sub-agent session has no
  binding row" at ERROR.

## @olive-mm

- 3.2.1: reported, with a patch, that a Discord approval card's buttons
  stayed live after the first press (#309).
- 3.0.0: reported, with a first implementation, the Discord channel approval
  gate (#305).

## Fazal

- 1.28.0: reported that approval-button payloads were not checked against a
  length budget.

## Karl M. Davis (@karlmdavis)

- 1.16.0: proposed provenance tracking for untrusted content (#37), which
  the read-conditioned sandbox egress verdicts are a slice of.

## Adding a line

A credit is written in the CHANGELOG entry of the release that carries the
change, and copied here in the same commit.
