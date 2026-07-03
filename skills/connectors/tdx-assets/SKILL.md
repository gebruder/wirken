---
name: tdx-assets
description: Look up staff devices, assets, and locations in TeamDynamix (TDX). Given a list of names, emails, or partial identifiers, resolve each person and return the assets assigned to them with location, model, ownership type, and status. Read-only.
disable-model-invocation: false
permissions:
  tools:
    allow: [http_request]
  credentials:
    allow: [tdx-api]
  egress:
    mode: allowlist
    domains: ["your-tenant.teamdynamix.com"]
  http:
    post_paths:
      - "https://your-tenant.teamdynamix.com/TDWebApi/api/APPID/assets/search"
  inference:
    allow: ["*"]
---

# TeamDynamix staff asset lookup

Look up the devices and locations assigned to staff in TeamDynamix.
The operator gives you a list of people (names, emails, or partial
identifiers, often messy); you resolve each to a TDX person, pull the
assets assigned to them, and return one table plus a section for names
you could not resolve cleanly.

## Authentication

Every request uses the `http_request` tool with `credential: tdx-api`.
The tool injects that credential host-side as the `Authorization: Bearer`
header; you never see the token value and must not put credentials in a
request body or a header yourself. There is **no login step** in this
skill: the `tdx-api` credential is already a TDX bearer token the
operator minted and stored.

If any call returns **HTTP 401**, the token has expired. **Stop
immediately**, do not retry, and tell the operator: "The `tdx-api`
credential has expired; refresh it (see INSTALL.md) and run again." You
cannot re-authenticate from inside this skill.

## Steps

1. **Resolve each person.** For each input identifier, call
   `http_request`:
   - method `GET`
   - url `https://your-tenant.teamdynamix.com/TDWebApi/api/people/lookup?searchText=<url-encoded identifier>&maxResults=10`
   - credential `tdx-api`

   The response is a JSON array of `User` objects. `people/lookup`
   returns the identity fields you need (`UID`, `FullName`,
   `PrimaryEmail`, `LocationName`, `IsActive`); it omits collection
   properties (`Attributes` among them) that this skill does not use.
   Prefer entries with `IsActive: true`. Then:
   - **Exactly one active match** → resolved. Keep `UID`, `FullName`,
     `PrimaryEmail`.
   - **More than one plausible match** → **ambiguous**. Do not auto-pick.
     Add the candidates (`FullName`, `PrimaryEmail`, `UID`) to the
     "Needs confirmation" section and move on.
   - **No match** → add the original identifier to the "Could not
     resolve" section. Never silently drop an input.

2. **Pull assets per resolved person.** For each resolved `UID`, call
   `http_request`:
   - method `POST`
   - url `https://your-tenant.teamdynamix.com/TDWebApi/api/APPID/assets/search`
   - credential `tdx-api`
   - body `{"OwningCustomerIDs": ["<UID>"], "MaxResults": 100}`

   The response is a JSON array of `Asset` objects. **Asset search does
   not return the `Attributes` collection** (custom attributes): you get
   base fields only, so location, model, ownership, and status come from
   this response, but the inventory date does not (step 3).

3. **Fetch inventory detail only when it is in play, and cap it.** The
   "Last inventory date" column comes from a tenant custom attribute in
   `Attributes[]`, which asset search omits. Fetch it per asset **only
   when** the inventory column is actually needed: the operator
   configured the attribute (see INSTALL.md) or the user asked for
   inventory dates. When it is needed, for each asset up to a cap of
   **25 detail fetches per run**, call `http_request`:
   - method `GET`
   - url `https://your-tenant.teamdynamix.com/TDWebApi/api/APPID/assets/<asset ID>`
   - credential `tdx-api`

   The response is a single `Asset` with `Attributes[]` populated. Read
   the configured attribute by `Name`; use its `ValueText` (or `Value`).
   - If the inventory column is not in play, write "not available".
   - If the tenant has no such attribute or it is empty, write "not
     available".
   - If you reach the 25-fetch cap, write "not available (not fetched,
     over cap)" for the remaining assets rather than issuing more
     requests. Both searches are rate-limited (60 requests per 60 seconds
     per IP); do not fan out unbounded detail fetches.

4. **Emit one table**, one row per (person, asset):

   | Person (input) | Resolved match | Location | Asset model | Ownership type | Last inventory date |
   |---|---|---|---|---|---|

   - Resolved match = `FullName` (`PrimaryEmail`).
   - Location = `LocationName`, plus `LocationRoomName` when present.
   - Asset model = `ProductModelName`.
   - Ownership type = "Person" when `OwningCustomerName` is set;
     "Department" when only `OwningDepartmentName` is set.
   - Last inventory date = the value from step 3, or one of the "not
     available" forms above. Do not invent a date.
   - A resolved person with zero assets gets one row with the asset
     columns blank and a note "no assets found".

5. **Then two sections below the table:**
   - **Needs confirmation**: ambiguous people, with their candidates,
     for the operator to disambiguate. Do not pick for them.
   - **Could not resolve**: input identifiers with no match, listed
     verbatim so nothing is lost.

## Errors and limits

- **401** → stop and ask for a token refresh (above). One occurrence
  ends the run.
- **429** → TDX rate-limits these endpoints (60 requests per 60 seconds
  per IP for the searches). Wait a few seconds and retry that one call
  once; if it is still 429, stop and report that TDX is rate-limiting.
  The 25-fetch detail cap in step 3 exists to keep large lists from
  triggering this.
- Any other non-2xx on a person's call → skip that person, note the
  status in "Could not resolve", and continue with the rest.
- Missing custom attributes → "not available", never an error.

## Read-only

This skill reads only; it never calls a create, update, or delete
endpoint. Read-only rests on two things: the tool refuses every write
verb (only `GET`, `HEAD`, and the one declared search POST are allowed),
and the TDX endpoints this skill uses are side-effect-free reads. Note
that a `GET` to any path on the bound TDX host carries the credential;
this skill confines itself by instruction to `people/lookup`,
`assets/search` (POST), and `assets/<id>`, and the operator's egress
allowlist confines every request to their TDX host.
