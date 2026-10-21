# Credentials and OAuth scopes

Wirken's credential vault is XChaCha20-Poly1305-encrypted under a device
key. The default build wraps the device key with a passphrase (Argon2id) in
`<data_dir>/keychain/`; builds with the `keychain-macos` or `keychain-linux`
feature keep it in the OS keychain. Two kinds of credentials live in it:

- **Raw secrets**: API keys, channel tokens, MCP server bearer
  tokens. Operators add these with `wirken credentials add`.
- **OAuth-managed credentials**: bootstrapped via `wirken mcp
  authorize <server>` against a known OAuth provider. The vault
  stores the access token, refresh token, and the granted scope
  set; the gateway refreshes the access token when it nears expiry,
  on the MCP proxy's request, and writes the vault. A plan sign-in
  for the `openai` provider (`wirken credentials authorize`) is an
  OAuth entry too: see [Plan sign-in](#plan-sign-in-openai).

Each entry is a **secret** or an **identifier**. Leak detection refuses
model-authored content, and content on its way to the model, that carries a
stored secret ([architecture.md](architecture.md#2-credential-lifecycle)); an
identifier (a phone number, a URL, a username, a project number) may appear
in messages and is not matched. An entry is a secret unless it is marked an
identifier: the nine built-in adapter identifiers (`teams-app-id`,
`matrix-homeserver`, `matrix-username`, `whatsapp-phone-number-id`,
`signal-endpoint`, `signal-phone-number`, `signal-allowed-senders`,
`google-chat-project-number`, `imessage-bluebubbles-url`) are marked when
stored, and an operator marks others with `wirken credentials add NAME
--identifier`. `wirken credentials list` and `show` print the kind. A secret
under 8 bytes is not matched, and the gateway names it in a warning at start.

## Which processes read the vault

- **The gateway** (`wirken run`) opens the vault. It resolves provider
  keys and `http_request` credentials, and reads each adapter's
  credentials when it spawns or respawns the adapter.
- **Adapters** never open the vault. Each starts with its own
  channel's credentials, which the gateway writes to its stdin, and
  gets no vault passphrase.
- **The MCP proxy** never opens the vault. At spawn the gateway
  writes to its stdin the names its `mcp.json` configs reference: the
  `vault:` env values of stdio servers and the `credential` of HTTP
  servers' bearer and OAuth auth, each OAuth credential without its
  refresh token. When an access token nears expiry the proxy asks the
  gateway, over a 0600 Unix socket that serves only the proxy's own
  process holding a token handed to it at spawn (on Windows, the token
  alone), to refresh it; the
  gateway refreshes only credentials it handed the proxy, calls the
  provider, writes the vault, and answers with the access token. The
  proxy gets no vault passphrase and never holds the device key or a
  refresh token. When an HTTP server refuses a credential (a 401, or
  `error="invalid_token"`), the proxy asks the gateway, on the same
  socket and under the same checks, for its current value, and the next
  call carries it: a credential rotated in the vault reaches an HTTP
  server without a restart. Each value sent is an
  `mcp_credential_refetched` row naming the credential. A stdio server's
  `vault:` values are fixed when it starts and change at the next
  gateway start.
- **`wirken` commands** that manage credentials (`credentials`,
  `channel add`, `setup`, `mcp authorize`) open the full vault in the
  operator's own process.

This page covers OAuth-managed credentials specifically: the
interactive scope picker, the non-interactive flags, and the
commands that inspect and re-grant existing OAuth credentials. For
raw-secret lifecycle (`add`, `rotate`, `remove`) see `wirken
credentials --help`.

## OAuth scope picker

When you authorize an OAuth-backed MCP server, wirken shows an
interactive picker listing the scopes the provider's catalog
supports. Required scopes are auto-included; the picker only
presents optional scopes for you to toggle.

```bash
wirken mcp authorize linear
wirken mcp authorize github
wirken mcp authorize google
```

Notion does not use OAuth scopes (Notion grants permissions per
workspace through its own connection UI), so wirken short-circuits
the picker for that provider and proceeds with no optional scopes.

After you submit the picker, wirken prints a confirmation section
listing every scope about to be requested (provider defaults,
required scopes, and your selected optional scopes) so you can
verify before the browser opens.

## Non-interactive scope selection

For scripted or CI use, three flags skip the picker:

```bash
wirken mcp authorize github --scope repo --scope read:org
```

Explicit scope selection. Repeat `--scope` for each id. Required
scopes are still auto-included. Unknown scope ids error with the
catalog listed.

```bash
wirken mcp authorize github --no-scopes
```

Minimum grant: required scopes only.

```bash
wirken mcp authorize github --all-scopes
```

Maximum grant: every scope in the provider's catalog.

If stdin is not a TTY and none of these flags are passed, wirken
exits with an error asking for an explicit scope selection.

The three flags are mutually exclusive at the clap layer; passing
more than one is a parse error.

## Inspecting and changing scopes

```bash
wirken credentials list
```

Shows credential name, channel, creation time, status, and a
SCOPES column. OAuth credentials display a scope count (for
example `5 scopes`); raw secrets display `n/a`. The footer points
operators at `wirken credentials show <name>` for detail.

```bash
wirken credentials show <name>
```

Pretty-prints one credential's non-secret metadata: channel,
timestamps, plus provider and the granted scope list for OAuth
credentials. The secret itself is never displayed; the function
routes OAuth credentials through a non-secret view that does not
carry the bearer tokens.

```bash
wirken credentials rescope <name>
```

Re-runs the OAuth authorization flow for an existing credential
with a new scope selection. The picker is pre-seeded with the
credential's currently-granted optional scopes so you can add or
drop without retyping the whole set. The same `--scope`,
`--no-scopes`, and `--all-scopes` flags are available for
scripted rescoping.

On success the vault row is replaced atomically. On cancel or
authorization failure the existing credential is left unchanged:
the function returns before any vault mutation.

Non-OAuth credentials cannot be rescoped; the command errors with
a typed message before any picker UI is rendered. Use `wirken
credentials rotate <name>` to replace a raw secret.

Every credentials verb reads the vault passphrase from
`WIRKEN_VAULT_PASSPHRASE` when it is set and prompts only when it is
not. `add` and `rotate` take the value from `--stdin` or
`--value-file`, so a setup script or a container entrypoint can store
or replace a credential with no terminal.

## Scope-not-granted failures

If a tool call fails because the OAuth credential is missing a
scope the tool needs, wirken detects the failure at the MCP
transport layer and surfaces a typed error to the agent. The
tool result reads:

```
Tool call refused: credential '<name>' missing scope <hint>.
Run: wirken credentials rescope <name>
```

When the provider's response named the specific scope, `<hint>`
carries the scope id. When the response indicated insufficient
scope generically, the message reads:

```
Tool call refused: credential '<name>' may be missing required
scope. Run: wirken credentials rescope <name> to review.
```

Detection is per-provider: GitHub REST 403 responses (e.g.
"Resource not accessible by integration"), Linear GraphQL
`FORBIDDEN` / `AUTHENTICATION_ERROR` extensions combined with
insufficient-permissions wording, and Google REST envelopes
carrying `insufficientPermissions` or "Request had insufficient
authentication scopes." Notion does not use OAuth scopes and is
not detected; its auth failures surface as generic tool errors.

Detectors are conservative. An auth error wirken cannot
classify with confidence falls through to the generic
tool-error path, where the operator sees the provider's raw
response. In that case the manual workflow still applies:

```bash
wirken credentials show <name>
wirken credentials rescope <name>
```

The detection logic is source-derived: each parser is built
against the provider's documented error format. The first
real-world failure that hits a detector either confirms the
shape or surfaces a refinement.

## Type-enforced secret redaction

Two layers protect against accidental token disclosure:

1. `wirken credentials show` and `wirken credentials list` route
   OAuth credentials through a non-secret view type that carries
   only `{ provider, scopes, expires_at, account, signed_in }`. The
   bearer tokens live
   exclusively inside the MCP-proxy crate; the display paths
   cannot read them, regardless of what a future contributor adds
   to the code.

2. The underlying `OAuthCredential` type (used by the OAuth flow
   internally) has a hand-written `Debug` impl that replaces
   `access_token`, `refresh_token` and `id_token` with `<redacted>` in any
   `{:?}`, `tracing!`, or `dbg!` output. There is no `Display`
   impl, so `{}` print is a compile error.

Together these mean a bearer token cannot reach stdout, stderr,
or the tracing log through ordinary Rust formatting. The encrypted
vault row remains the only place the secret exists outside of an
in-flight HTTP request.

## Plan sign-in (openai)

The `openai` provider can run an agent on the operator's own ChatGPT plan
instead of an API key, through OpenAI's sign-in for open-source apps
(https://developers.openai.com/siwc/token-sharing-open-source). It is opt-in:
nothing changes for an installation that never signs in.

```bash
wirken credentials authorize                 # entry openai-plan
wirken credentials authorize work --port 1455 --no-browser
```

`wirken setup` and `wirken agents add` offer the same sign-in as the provider
"OpenAI with your ChatGPT plan (Continue with ChatGPT)", then list the signed-in
account's models to pick from.

### What a sign-in does

1. The host id is read from `<data_dir>/plan-host-id`, or created there
   (mode 0600) as `urn:uuid:<random v4 UUID>` before anything is sent. It
   identifies the host to OpenAI, is not a credential, and is not in the
   vault. A file holding anything else is an error, not replaced.
2. A loopback listener starts on `127.0.0.1` (any free port, or `--port`) at
   the path `/auth/callback`, before the browser opens. A fresh state, OpenID
   nonce and PKCE verifier (S256) are made for the attempt.
3. The browser opens `https://auth.openai.com/api/accounts/authorize` with
   the scopes `openid profile email offline_access resource.invoke
   chatgpt.tokens.use.direct`, `resource=https://api.openai.com/v1` and the
   host id. A first sign-in sends `client_id=dynamic_agent_client` and
   `agent_name_hint=Wirken`, which registers the app for that account. A
   later sign-in to the same entry sends the client id issued then, the
   retained ID token as `id_token_hint` and the email as `login_hint`, and no
   name hint. With `--no-browser` the URL is printed; it carries the ID token
   hint on a reauthorization and is not logged.
4. The callback's state is checked first. `error=access_denied` (consent
   declined), any other error, or a mismatched state ends the attempt with no
   code exchange. A first registration must return the issued client id; a
   reauthorization may leave it out and keeps the saved one, and one naming a
   different client id is refused.
5. The code is exchanged at `https://auth.openai.com/api/accounts/oauth/token`
   with the client id, the verifier, the same redirect URI and the resource.
   No client secret exists.
6. The ID token is validated before anything is kept: an RS256 signature by
   a key in the JWKS that the discovery document
   (`https://auth.openai.com/.well-known/openid-configuration`) names, the
   issuer, the issued client id as audience, expiry, and the nonce of this
   attempt. Its `sub` is the account's identity; a reauthorization that comes
   back as a different `sub` replaces nothing.
7. Plan usage counts only when `chatgpt.tokens.use.direct` is in the scopes
   the sign-in's token response returned. When it is absent, or that response
   carries no `scope`, no usable credential is stored: the new session is revoked, a
   first sign-in keeps its registration without tokens so a later attempt
   reuses the client id (and asks for consent again), and the command says
   plan usage was not granted.

The vault entry (channel `oauth`, kind `plan_sign_in`) holds the issued
client id, the issuer, the account `sub` and email, the ID token, the access
and refresh tokens, their expiry and the granted scopes. The kind is bound
into the entry's encryption (its AEAD associated data is the name, a NUL and
the kind), so no command reads it as an API key, and a Wirken release from
before plan mode, which decrypts every entry under its name alone, fails to
read it instead of sending it to a provider. Every other entry is encrypted
as before. `wirken credentials list` shows the account
beside the scope count and marks a signed-out entry; `show` prints the
account and whether it is signed in.

The first sign-in on a data directory that grants plan usage prints "You're
using your ChatGPT plan", once. Requests from a plan agent show "Using
ChatGPT plan" with a "Manage usage" link
(https://chatgpt.com/settings/usage) beside the agent in the WebChat status
strip, and `wirken run` prints it on the provider line.

### Refresh

The access token lives an hour and the refresh token thirty days, replaced on
every refresh. Each model call asks a token source for the bearer; it
refreshes when the access token is within five minutes of expiry, sending the
client id, the refresh token and the resource, and no scope. A refresh
answer that omits `scope` keeps the granted scopes already stored; one that
names scopes replaces them, and plan usage is off if
`chatgpt.tokens.use.direct` is no longer among them.

- In the gateway, every agent on one entry shares one token source, so one
  refresh at a time per entry.
- Across processes (`wirken run`, `wirken ask`, `wirken agents set --model
  list`), a refresh holds the entry's lock file
  (`<data_dir>/plan-<hash of the entry name>.lock`, mode 0600) from reading
  the entry to writing the result, waiting up to 90 seconds for another
  process to release it. A process that finds the stored refresh token
  changed when it gets the lock uses the tokens the other process stored.
- The vault is read and written in short steps; the request to OpenAI runs
  with no vault transaction open, so other credential use is not held up by
  a slow token endpoint. The write still checks that the stored refresh token
  is the one the refresh started from, and if the entry changed meanwhile (a
  new sign-in or an import) it keeps what is stored.
- A network error, a 5xx or another non-terminal answer keeps the
  credential. The current access token is used while it is valid for more
  than a minute; after that the call fails and the next one tries again. An
  expired token is never sent.
- `invalid_grant`, `invalid_refresh_token`, `token_expired`,
  `refresh_token_expired`, `refresh_token_invalidated` or
  `refresh_token_reused` clears both tokens and keeps the client id, the
  account and the host id; the next call says to run `wirken credentials
  authorize <entry>`. `invalid_client` fails the call as a configuration
  error.
- If the vault write fails after a successful refresh, the process keeps the
  new tokens in memory, logs an error, and retries the write on the next
  call.

There is no fallback: a plan agent whose credential is unusable fails its
calls; it never switches to an API key or another provider.

### Sign-out and removal

```bash
wirken credentials sign-out [ENTRY]
wirken credentials remove ENTRY
```

`sign-out` holds the entry's lock file, clears the access and refresh tokens
in the vault, keeping the client id, the account, the ID token and the host id
for the next sign-in, and then revokes the old refresh token at the
revocation endpoint the discovery document names (`token`,
`token_type_hint=refresh_token` and the client id; an empty 200 is success),
retrying a network error or 5xx after 1, 2 and 4 seconds. No vault
transaction is open during the revocation. When revocation was not confirmed it says so; the app's
access can also be removed at https://chatgpt.com/settings/usage. `remove`
on a plan entry does the same before deleting it.

### Headless and self-hosted hosts

The callback goes to `127.0.0.1` on the machine running the browser, so a
host without one follows OpenAI's self-hosted VM procedure: sign in on a
machine with a browser, move the credential, and let the remote host own
refreshes under its own host id.

```bash
# on the machine with a browser
wirken credentials authorize openai-plan
wirken credentials export-plan openai-plan --out plan.json
# copy plan.json over a secure channel (scp, for example), then on the host
wirken credentials import-plan openai-plan --from plan.json
```

`export-plan` writes a new owner-only file and clears the tokens on the
exporting machine, since only one host may hold a rotating refresh token.
`import-plan` creates the host's own `plan-host-id` first if it has none; the
file carries no host id. Delete the file on both machines afterwards. The next
sign-in on the remote host sends its own host id.

### Errors

A refused request keeps the HTTP status, the error code and OpenAI's
`x-request-id` in the error and in the failed call's `llm_request_failed`
audit row. `subscription_sharing_usage_limit_exceeded` (HTTP 429, or inside
the stream as `response.failed`) is never retried and reads "Usage limit
reached. Review your plan or this app's limit in ChatGPT settings." with the
Manage usage link; WebChat shows it as a usage-limit block with that link. A
503 (`subscription_sharing_usage_unavailable`,
`subscription_sharing_user_unavailable`, or a routing refusal) is retried
after 1, 2 and 4 seconds. The other `subscription_sharing_*` and
`chatpass_v2_*` codes, and a `{"detail": ...}` refusal before the request
starts, fail the call without a retry. A reply counts only when the stream
reaches `response.completed`; a stream that ends before it is an error.
