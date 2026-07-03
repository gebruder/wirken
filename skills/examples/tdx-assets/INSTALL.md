# Installing tdx-assets

For whoever installs this skill. Steps 1-5 are one-time; step 6 (token
refresh) is recurring until issue
[gebruder/wirken#178](https://github.com/gebruder/wirken/issues/178) lands.

## 1. Copy the skill

```bash
cp -r tdx-assets ~/.wirken/skills/tdx-assets/
```

## 2. Sign it (preferred) or opt into unsigned

Wirken refuses unsigned skills at load by default. Sign it:

```bash
wirken skills sign ~/.wirken/skills/tdx-assets/
```

The alternative, `WIRKEN_ALLOW_UNSIGNED_SKILLS=1`, loads the skill
without a signature. Prefer signing: an unsigned skill is only as
trustworthy as the directory it sits in, and a signature makes any
later edit to `SKILL.md` fail the load-time check instead of silently
taking effect. Use the env var only for a throwaway test.

## 3. Point the skill at your tenant

Edit `~/.wirken/skills/tdx-assets/SKILL.md`:

- Replace `your-tenant.teamdynamix.com` (in `egress.domains` **and** both
  `http.post_paths`) with your TDX hostname. Use `/SBTDWebApi/` instead
  of `/TDWebApi/` if this is a sandbox instance.
- Replace `APPID` in the asset-search `post_paths` entry with the numeric
  id of your Asset application (TDX Admin → Applications).

These two values are the only things the tool matches against, so they
must be exact. Re-sign after editing (step 2).

## 4. Mint a TDX bearer token

The skill uses a bearer token; it does **not** log in (the tool injects
credentials only as an `Authorization: Bearer` header, never into a
request body). Mint a token out of band with either TDX auth type:

- **Admin (recommended for an unattended integration).** A key-based
  service account: `POST /TDWebApi/api/auth/loginadmin` with a JSON body
  `{"BEID": "...", "WebServicesKey": "..."}`. The `BEID` and
  `WebServicesKey` are on the organization detail page in TDAdmin (needs
  the "Add BE Administrators" permission; the service account must be
  Active). Broad read access, no human in the loop.
- **User.** `POST /TDWebApi/api/auth/login` (or `/api/auth`) with
  `{"UserName": "...", "Password": "..."}`. Works only if that user can
  read both People and the Asset application.

Either returns the token as a plain-text JWT string. The token's account
must be able to read People and the Asset application (see reference.md).

## 5. Store the token, bound to your TDX host

```bash
wirken credential add tdx-api --host your-tenant.teamdynamix.com
```

Paste the JWT when prompted. `--host` binds the credential in the vault
to your TDX hostname: the tool refuses to send it anywhere else, and no
skill can widen that. The credential name `tdx-api` matches the skill's
`credentials.allow`.

## 6. Refresh the token every 24 hours (until #178)

**TDX bearer tokens expire 24 hours after they are issued.** When the
token expires, the next query returns 401 and the skill stops and asks
you to refresh. Re-mint (step 4) and re-store (step 5, same command,
overwrites) daily, or script it.

This daily refresh is the one manual dependency the skill still has. It
goes away when
[gebruder/wirken#178](https://github.com/gebruder/wirken/issues/178) (a
credential-exchange resolver that mints and renews the token host-side
from the `BEID`/`WebServicesKey`) lands; at that point you store the key
once and the resolver self-renews.

## Using it

Two forms, both work with `disable-model-invocation: false`:

```
/tdx-assets Jane Doe, jsmith@example.edu, "Rob Lee (facilities)", 774-0123
```

or natural language: "look up the devices assigned to Jane Doe and
jsmith@example.edu in TeamDynamix."

## What is enforced (by wirken, not by trust)

- **Credential bound to your TDX host, at the vault layer.** `tdx-api`
  is only ever sent to the host you bound it to; a request to any other
  host is refused before anything leaves the process, and the skill's
  own permissions cannot widen that.
- **Egress allowlisted.** The skill can reach only the hostname in its
  `egress.domains`.
- **Read-only plus two declared POST paths.** Only `GET`/`HEAD` and the
  two search endpoints in `http.post_paths` are allowed; any other path
  or verb (create/update/delete) is refused at the gate.
- **Every call audited.** Each request lands a `http_request` row in the
  session hash chain (method, host, path, status, credential name — never
  the token value); the chain verifies with `wirken audit verify`.

## What is NOT enforced (limitations, from the design note)

- **Token refresh** is manual and daily (above), until #178.
- **DNS rebinding.** The binding is by hostname. If your TDX hostname
  resolved to a hostile address (DNS compromise) the request would still
  go there; the tool checks names, not resolved IPs.
- **A server echoing the token.** The tool redacts the token from every
  result and audit row, but if TDX itself reflected the `Authorization`
  header back in a response body, that body is returned to the model. TDX
  does not do this; it is a property of trusting the bound host.
- **Port scoping.** Binding a host authorizes it on any port over https,
  not just 443.
- **Request-body content.** The model composes the search bodies; the
  tool does not inspect them. They only ever reach your bound TDX host.
