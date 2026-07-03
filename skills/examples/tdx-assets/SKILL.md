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
      - "https://your-tenant.teamdynamix.com/TDWebApi/api/people/search"
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
   - method `POST`
   - url `https://your-tenant.teamdynamix.com/TDWebApi/api/people/search`
   - credential `tdx-api`
   - body `{"SearchText": "<the identifier>", "IsActive": true, "MaxResults": 10}`

   The response is a JSON array of `User` objects. Then:
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

   The response is a JSON array of `Asset` objects.

3. **Emit one table**, one row per (person, asset):

   | Person (input) | Resolved match | Location | Asset model | Ownership type | Last inventory date |
   |---|---|---|---|---|---|

   - Resolved match = `FullName` (`PrimaryEmail`).
   - Location = `LocationName`, plus `LocationRoomName` when present.
   - Asset model = `ProductModelName`.
   - Ownership type = "Person" when `OwningCustomerName` is set;
     "Department" when only `OwningDepartmentName` is set.
   - Last inventory date: TDX has no base inventory-date field. Read it
     from the tenant custom attribute the operator identified in
     `Attributes[]` (match on the attribute `Name`, use its `ValueText`
     or `Value`). If the tenant has no such attribute or it is empty,
     write **"not available"** — do not error and do not invent a date.
   - A resolved person with zero assets gets one row with the asset
     columns blank and a note "no assets found".

4. **Then two sections below the table:**
   - **Needs confirmation** — ambiguous people, with their candidates,
     for the operator to disambiguate. Do not pick for them.
   - **Could not resolve** — input identifiers with no match, listed
     verbatim so nothing is lost.

## Errors and limits

- **401** → stop and ask for a token refresh (above). One occurrence
  ends the run.
- **429** (rate limited) → wait a few seconds and retry that one call
  once; if it is still 429, stop and report that TDX is rate-limiting.
- Any other non-2xx on a person's call → skip that person, note the
  status in "Could not resolve", and continue with the rest.
- Missing custom attributes → "not available", never an error.

## Read-only

Use only the two declared search endpoints. Never call a create,
update, or delete endpoint. The skill's permissions allow only these two
POST paths and `GET`/`HEAD`; the tool refuses anything else.
