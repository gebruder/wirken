# TeamDynamix Web API reference (for tdx-assets)

Field names below are taken verbatim from the tenant-independent
OpenAPI 3.0 contract at
`https://solutions.teamdynamix.com/TDWebApi/swagger/v1/openapi.json`
(the product-level contract document; every tenant serves the same shape
at its own hostname). **Verify every field name against your own tenant's
`/TDWebApi/swagger/v1/openapi.json` before first production use** — the
check is a same-file diff against your tenant URL. Fields that are
tenant-configured (custom attributes) are marked **[tenant]**.

Base path is `/TDWebApi/api` on production and `/SBTDWebApi/api` on a
sandbox instance; adjust the URLs to match your instance.

## Authentication model (what this skill relies on)

TDX credentials are submitted **in the request body** to a login
endpoint, which returns a **bearer token (JWT)** as a plain string. The
`http_request` tool injects a credential only as the
`Authorization: Bearer` header and never into a body, so **this skill
does not log in**. The `tdx-api` credential must already be a minted
bearer token (see INSTALL.md). The token **expires 24 hours after
issue**; on expiry a call returns 401 and the skill stops for a refresh.

Login endpoints (used by the operator out of band, not by the skill):

- `POST /api/auth` ← `LoginParameters { UserName, Password }` → token string.
- `POST /api/auth/loginadmin` ← `AdminTokenParameters { BEID, WebServicesKey }` → token string.

## People search

`POST /api/people/search`

Request body: `UserSearch`. Relevant fields (all optional):

- `SearchText` (string) — LIKE match across name / username / email.
- `IsActive` (boolean) — the skill sets `true` to prefer current staff.
- `MaxResults` (integer) — result cap; the skill sets `10` to detect ambiguity.
- Other narrowing fields available: `UserName`, `PrimaryEmail` is **not**
  a search field (search by `SearchText`), `ExternalID`, `AlternateID`,
  `IsEmployee`, `IsConfidential`, `PhoneNumber`, `AccountIDs` (array int),
  `ReferenceIDs` (array int), `SecurityRoleID`, `AppName`.

Response: **array of `User`** (a plain JSON array, not a paged wrapper;
`MaxResults` bounds it). Fields the skill reads:

- `UID` (string, GUID) — the person's unique id; passed to asset search.
- `FullName`, `FirstName`, `LastName`.
- `PrimaryEmail`, `AlternateEmail`.
- `UserName`, `ExternalID`, `AlternateID`, `ReferenceID`.
- `IsActive`, `IsEmployee`.
- `LocationName`, `LocationRoomName` (the person's default location).
- `Attributes` (array of `CustomAttribute`) — **[tenant]**.

## Asset search

`POST /api/{appId}/assets/search` — `{appId}` is the numeric id of the
tenant's Asset/CI application; the installer substitutes it (`APPID` in
the skill's `post_paths`).

Request body: `AssetSearch`. Relevant fields (all optional):

- `SearchText` (string) — LIKE match.
- `SerialLike` (string) — serial-number LIKE match.
- `OwningCustomerIDs` (array of string UID) — the skill sets `["<UID>"]`
  to find assets **owned** by the resolved person.
- `MaxResults` (integer) — result cap; the skill sets `100`.
- Other narrowing fields: `StatusIDs` (array int), `LocationIDs`
  (array int), `RoomID` (int), `ProductModelIDs` (array int),
  `ManufacturerIDs` (array int), `UsingCustomerIDs` (array string, assets
  a person currently *uses* rather than owns), `RequestingCustomerIDs`,
  `SupplierIDs`, `IsInService` (boolean), `CustomAttributes`
  (array `CustomAttribute`) **[tenant]**, plus date-range fields
  (`CreatedDate*`, `ModifiedDate*`, `AcquisitionDate*`,
  `ExpectedReplacementDate*`, `ContractEndDate*`).

Note on "assigned": this skill searches `OwningCustomerIDs` (owner). If
your tenant tracks device custody separately, `UsingCustomerIDs` (the
current user) may be what you want; that is a per-tenant choice.

Response: **array of `Asset`** (plain array, `MaxResults` bounded).
Fields the skill reads:

- `ID`, `Name`, `SerialNumber`, `Tag`, `ExternalID`.
- `ProductModelName` (`ProductModelID`), `ManufacturerName`.
- `LocationName`, `LocationRoomName` (`LocationID`, `LocationRoomID`).
- `OwningCustomerName` (`OwningCustomerID`) — set when a person owns it.
- `OwningDepartmentName` (`OwningDepartmentID`) — set when a department owns it.
- `StatusName` (`StatusID`).
- `Attributes` (array of `CustomAttribute`) — **[tenant]**.

### No base "last inventory date" field

The `Asset` schema has **no** inventory / audit / last-seen date field.
Its date fields are `AcquisitionDate`, `CreatedDate`, `ModifiedDate`,
`ExpectedReplacementDate` — none is an inventory date. If your tenant
records a "last inventory" date, it lives in `Attributes[]` as a custom
attribute; identify its attribute `Name` during acceptance and configure
the skill to read it. If there is none, the skill writes "not
available". Do not hunt for a base field; there isn't one.

## Custom attributes (`CustomAttribute`) — [tenant]

Both `User.Attributes` and `Asset.Attributes` are arrays of
`CustomAttribute`. Fields: `ID` (int), `Name` (string), `Value` (string,
the raw/id value), `ValueText` (string, the display value),
`DataType`, `FieldType`, `Choices`, `ChoicesText`, `Order`, `SectionID`,
`SectionName`. Match on `Name`; prefer `ValueText` for display. Which
attributes exist is entirely tenant-defined.

## Permissions the bearer token needs — [tenant]

The endpoints are permission-gated per the account behind the token, not
by a fixed rule in the spec:

- People search needs a token whose account can read the People/directory.
- Asset search needs a token whose account can access the Asset
  application (`{appId}`).

An **admin** token (`/api/auth/loginadmin` with `BEID` + `WebServicesKey`)
is a service account with broad read access and is the reliable choice
for an unattended integration. A **user** token (`/api/auth` with
`UserName` + `Password`) works only if that user holds both permissions.
Either way the token is a 24-hour bearer; see INSTALL.md.

## Pagination

Both search endpoints return a **plain JSON array** capped by
`MaxResults`; there is no cursor or page token. To get more than the cap,
raise `MaxResults` or narrow the search.
