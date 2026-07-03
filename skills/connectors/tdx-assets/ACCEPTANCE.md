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
  your tenant's schema for `User`, `AssetSearch`, `Asset`,
  `CustomAttribute` (and `UserSearch` if you switch to the people-search
  POST alternative). The product-level contract and your tenant serve the
  same shape, so this is a same-file diff.
- [ ] **Asset application id.** Confirm the `APPID` you put in the
  `post_paths` entry and the body URLs is your Asset application's numeric
  id.
- [ ] **Last-inventory custom attribute, read via detail GET.** Asset
  **search omits `Attributes`**, so the inventory date is read only via
  `GET /api/APPID/assets/<id>`. Identify the `Attributes[]` custom
  attribute your tenant uses for last inventory (its `Name`) and confirm
  `GET /api/APPID/assets/<id>` returns it populated, or confirm there is
  none (the skill then writes "not available"). Configure the skill body
  with the attribute `Name`.
- [ ] **Token permissions.** Confirm the account behind `tdx-api` can
  read People and the Asset application (the people-search POST
  alternative additionally lists `TDPeople`).

## Behavior (real tenant + agent)

The skill body's decisions (resolve, surface ambiguous, could-not-resolve,
401-stop, 429-backoff, non-2xx skip, zero-assets, not-available) are agent
behavior against your data, not code-enforced, so every behavior the body
promises is exercised here:

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
- [ ] **429 backoff (in your sandbox instance).** TDX limits the searches
  to 60 requests / 60s / IP (people/lookup 75 / 10s). Deliberately driving
  a production tenant into rate limiting can get the integration account
  flagged, so do this in your sandbox: drive enough queries to hit the
  limit, then confirm the skill waits and retries the one call once, stops
  and reports rate-limiting if it is still 429, and that the 25-fetch
  detail cap keeps large lists from fanning out.
- [ ] **Non-2xx skip-and-note.** Force a non-2xx other than 401/429 (for
  example, request asset detail with an invalid asset id for a 404, or use
  a token whose account lacks the Asset application for a 403 on that leg);
  confirm that person lands in "Could not resolve" with the status noted
  and the run continues with the rest.
- [ ] **Zero assets.** A resolved person with no assets; confirm one row
  with blank asset columns and "no assets found", not a dropped person.
- [ ] **"Not available" rendering.** Confirm the inventory column shows
  the real attribute value when the detail GET returns it, "not available"
  when the attribute is absent or not in play, and "not available (not
  fetched, over cap)" when the 25-fetch cap is reached.

## Binding and audit

- [ ] **Egress refusal.** With the **unmodified** skill, ask it to fetch
  a host outside `egress.domains`. The egress allowlist refuses it before
  anything leaves the process (nothing on the wire).
- [ ] **Binding refusal.** In a **test copy**, widen `egress.domains` to
  include a non-TDX host, then aim a request there. Egress now permits it,
  so the refusal comes from the vault instead: `tdx-api` is bound to your
  TDX host and is refused for the other host (again, nothing on the wire).
  These are two different controls; check both.
- [ ] **Audit chain.** After a run, confirm `http_request` rows are
  present and the chain verifies, using an **out-of-band** anchor (not
  the co-resident default):

  ```bash
  wirken audit verify --require-signed --anchor /path/outside/data-dir/audit-signing.pub
  ```

  A co-resident anchor now prints a warning (see docs/audit-cli.md); use
  a pinned anchor held outside `~/.wirken` for a tamper-evident check.
