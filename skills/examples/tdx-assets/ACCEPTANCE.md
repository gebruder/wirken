# Acceptance checks (need a live TDX tenant)

These need a real TDX tenant, so they can't be checked from the skill
source alone. Run them before first production use. The checks that do
not need a tenant (skill loads/signs, slash interceptor, system-prompt
gating, credential binding, egress allowlist, POST-path gate, negative
host/binding) already pass; see the verification output in the report.

## Contract

- [ ] **Field diff against your tenant.** Fetch
  `https://<your-tenant>.teamdynamix.com/TDWebApi/swagger/v1/openapi.json`
  and confirm every field name this skill uses (see reference.md) matches
  your tenant's schema for `UserSearch`, `User`, `AssetSearch`, `Asset`,
  `CustomAttribute`. The product-level contract and your tenant serve the
  same shape, so this is a same-file diff.
- [ ] **Asset application id.** Confirm the `APPID` you put in
  `post_paths` is your Asset application's numeric id.
- [ ] **Last-inventory custom attribute.** TDX has no base
  inventory-date field. Identify the `Attributes[]` custom attribute your
  tenant uses for last inventory (its `Name`), or confirm there is none
  (the skill then writes "not available").
- [ ] **Token permissions.** Confirm the account behind `tdx-api` can
  read People and the Asset application.

## Behavior (real tenant + agent)

The skill body's decisions (resolve, surface ambiguous, could-not-resolve,
401-stop, 429-backoff) are agent behavior against your data, not
code-enforced, so they must be exercised live:

- [ ] **End-to-end, both forms.** Run `/tdx-assets <staff list>` and the
  natural-language form against your sandbox. Confirm the table has the
  six columns and that resolved people show their assets.
- [ ] **Deliberate misspelling.** Include one clearly-wrong name; confirm
  it lands in "Could not resolve" and is not silently dropped or
  auto-matched.
- [ ] **Ambiguity.** Include a name with more than one active match;
  confirm it lands in "Needs confirmation" with candidates, not auto-picked.
- [ ] **Token reuse.** Run two queries in one session. Confirm both use
  the stored bearer token and the skill makes **no** `/api/auth` call
  (it has none; it authenticates by header injection only).
- [ ] **Expiry.** After the token is >24h old, confirm a query returns
  401 and the skill stops and asks for a refresh rather than retrying.

## Binding and audit

- [ ] **Host binding.** Point one request at a non-TDX host (e.g. edit a
  test copy of the skill's `egress.domains`/`post_paths`, or ask it to
  fetch another host). Confirm it refuses and nothing leaves the process;
  and that a `tdx-api` credential bound to a different host is refused.
- [ ] **Audit chain.** After a run, confirm `http_request` rows are
  present and the chain verifies, using an **out-of-band** anchor (not
  the co-resident default):

  ```bash
  wirken audit verify --require-signed --anchor /path/outside/data-dir/audit-signing.pub
  ```

  A co-resident anchor now prints a warning (see docs/audit-cli.md); use
  a pinned anchor held outside `~/.wirken` for a tamper-evident check.
