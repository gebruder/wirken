# Proxy identity

A client of the proxy listener can present a JWT from the organization's
identity provider in place of a token Wirken issued. Wirken verifies the JWT
and gives the caller a grant set the operator mapped it to: what a token
carries, held per subject. The mode as a whole starts at [proxy.md](proxy.md);
tokens are in [inference-proxy.md](inference-proxy.md#tokens).

Wirken is not an identity provider. It holds no accounts, runs no sign-in and
issues no identity token. A caller with no JWT of the configured issuer has no
way here to get one. Hand-issued tokens work as before, beside JWTs.

## Turning it on

An `oidc` block in `proxy.json`:

```json
"oidc": {
    "issuer": "https://idp.example.com/realms/acme",
    "audience": "wirken-proxy",
    "grant_claim": "groups",
    "max_token_lifetime_secs": 900
}
```

| Field | Default | Meaning |
|---|---|---|
| `issuer` | required | The issuer, exactly as in a JWT's `iss`. `https`; plain `http` for a loopback host only. |
| `audience` | required | A JWT's `aud` must name it. |
| `max_token_lifetime_secs` | required | The longest a JWT is accepted after its `iat`, whatever its `exp` says. See [Revocation](#revocation). |
| `grant_claim` | none | The claim whose value selects a grant set: a string or a list of strings. See [Mapping](#mapping). |
| `jwks_file` | none | A file holding the issuer's keys as a JWK set, relative to the data directory unless absolute. See [Keys](#keys). |
| `algorithms` | all below | The signature algorithms accepted, to narrow the list. |
| `clock_skew_secs` | 60 | How far the issuer's clock may be from this host's. At most 300. |
| `jwks_cache_secs` | 3600 | How long fetched keys are used before they are fetched again. |
| `record_subject` | `false` | Record the subject on each row as issued, in place of its keyed hash. |
| `subject_key` | `proxy-subject-key` | The vault entry holding the key subjects are hashed under. Made on first use. |
| `exchange` | none | The client Wirken is at the issuer's token endpoint, to exchange a caller's JWT for an MCP server that acts for the caller. See [Token exchange](#token-exchange). |

There is one issuer. Without the block a JWT is an unknown token.
`wirken run` prints the issuer and how many keys it holds at start.

## What is verified

A bearer or `x-api-key` value that is three base64url parts and does not start
with `wkp_` is read as a JWT. In order:

1. `iss` is the configured issuer, character for character.
2. `alg` is one of `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`,
   `ES256`, `ES384`, `EdDSA`. A shared-secret algorithm (`HS256` and its kin)
   and `none` are refused, and cannot be configured.
3. The signature verifies under the issuer's key the JWT names by `kid`. A JWT
   that names no key is verified where the issuer has exactly one key for its
   algorithm.
4. `aud` names the configured audience.
5. `exp` and `iat` are present; `iat` and `nbf` are not ahead of the clock;
   the JWT is not past `exp`, nor older than `max_token_lifetime_secs`.
6. `sub` is present. `jti` is recorded where there is one.

The same check is made at the MCP endpoint ([proxy-mcp.md](proxy-mcp.md)).

## Keys

Without `jwks_file` the keys are fetched from the issuer: its discovery
document at `<issuer>/.well-known/openid-configuration`, then the `jwks_uri`
that document names. Both are fetched over HTTPS, or plain HTTP for a loopback
issuer, and no redirect is followed. The document must name the configured
issuer, and `jwks_uri` must be on the issuer's origin. Keys are kept for
`jwks_cache_secs`. A JWT naming a key the set does not hold causes one fetch,
at most once a minute.

With `jwks_file` the keys are read once at start and the issuer is never
asked. This is the route for a host with no path to the issuer, and for an
issuer that publishes its keys on another origin. A file that cannot be read,
holds a private key or holds no usable key stops the start.

An issuer that cannot be reached, with no pinned keys, verifies nothing: every
JWT is refused with `jwt_keys_unavailable` until a fetch works. Keys past
`jwks_cache_secs` are not used. Tokens Wirken issued are not affected.

## Mapping

A grant set is what a token carries: upstreams, models, ceilings, and the MCP
servers of one agent. A mapping gives a grant set to the JWTs whose
`grant_claim` holds a value, or to one subject.

```bash
wirken proxy identity grant-set set engineers --upstream anthropic --ceiling-usd 20
wirken proxy identity map engineers --claim-value eng
wirken proxy identity map engineers --subject alice@example.com
wirken proxy identity unmap --claim-value eng
wirken proxy identity grant-set remove engineers
wirken proxy identity list
```

Each change is made at a terminal, refuses inside a Wirken `exec`, and is an
`operator_command` row. A subject is named on that row as on the rows of its
calls: by its keyed hash, or as issued with `record_subject`. A mapping is for
the configured issuer; one written for another issuer matches nothing.

- The claim selects. Where none of its values is mapped, the subject does.
- A JWT no mapping matches gets nothing: `jwt_no_grant`, 403.
- A JWT whose values are mapped to different grant sets is refused:
  `jwt_ambiguous_grant`, 403. Values mapped to one grant set select it.
- A grant set a mapping names cannot be removed.

Ceilings are per subject. Each subject's calls and spend are counted on their
own, under `proxy-subject:<id>` in `budget.db`; a grant set's ceiling is not
shared among the subjects it is given to.

## Revocation

There is no deny list. A JWT is accepted for at most
`max_token_lifetime_secs` after its `iat`, and for less where its `exp` comes
first. A grant withdrawn at the identity provider stops at the next JWT the
caller needs. Removing a mapping, or changing a grant set, takes effect at the
next request.

## What is recorded

Every row of a call made with a JWT carries `identity`:

| Field | Meaning |
|---|---|
| `issuer` | The configured issuer. |
| `grant_set` | The grant set applied. Absent on a refusal of a JWT that selected none. |
| `jti` | The JWT's `jti`, where it has one. |
| `subject_hash` | HMAC-SHA256 of the issuer and the subject under the vault key, in hex. |
| `subject` | The subject as issued, in place of `subject_hash`, with `record_subject`. |

The JWT is on no row. `token_id` on these rows is the subject's id, `u` and
the first sixteen characters of its hash, and the lane is
`proxy-<subject id>-<label>`; `token_name` is the grant set. The sender of a
tool call is `proxy-subject:<id>`.

A JWT that is refused is a `proxy_refused` row on the `gateway-proxy` lane, at
most one a second together with unknown tokens:

| `reason` | When | Status | `identity` |
|---|---|---|---|
| `jwt_invalid` | Malformed, an algorithm not accepted, a signature no key of the issuer made, a claim missing or not yet valid. | 401 | no |
| `jwt_expired` | Past `exp`, or older than `max_token_lifetime_secs`. | 401 | no |
| `jwt_wrong_issuer` | `iss` is not the configured issuer. | 401 | no |
| `jwt_wrong_audience` | `aud` does not name the configured audience. | 401 | no |
| `jwt_keys_unavailable` | The issuer's keys could not be had. | 503 | no |
| `jwt_no_grant` | Verified, and no mapping matches. | 403 | yes |
| `jwt_ambiguous_grant` | Verified, and mappings name more than one grant set. | 403 | yes |

A refusal after the grant set is applied (a model not allowed, a ceiling
reached) is on the subject's own lane, with `identity`.

## Token exchange

An MCP server can act for the person behind a call rather than for Wirken.
Its signed entry names the audience the downstream system is known by at the
identity provider:

```json
"crm": {
    "transport": "http",
    "url": "https://crm.example.com/mcp",
    "exchange": {"audience": "crm-api"}
}
```

A `tools/call` at the MCP endpoint ([proxy-mcp.md](proxy-mcp.md)) made with a
JWT, to one of that server's tools, is made with a token the issuer gave for
that JWT. Wirken sends the JWT to the issuer's token endpoint as the subject
token of an RFC 8693 exchange and asks for an access token of the entry's
audience. The downstream gets the token the issuer exchanged the JWT for, and
sees the caller's subject and its own audience.

- An HTTP server gets the token as the bearer of the call, in place of the
  entry's `auth`. `initialize` and `tools/list` are sent at start, before
  there is a caller, with the entry's `auth`, or none.
- A stdio server needs a `sandbox` block with `inject`
  ([mcp.md](mcp.md#injecting-a-credential)). While the call runs, its
  injected route sets the token in place of the entry's credential, and each
  `mcp_credential_injected` row of the call names the audience in
  `exchanged_for`. The server never holds the token. The proxy makes one
  call at a time, so the token a request gets is that of the call the server
  is answering.

The `exchange` block is inside the signed hash: adding one, or changing its
audience, needs `wirken mcp sign` again. An entry whose block cannot be
served (a stdio server without `inject`, an audience that is not one word of
printable ASCII) is not started: `mcp_entry_refused` with `exchange_invalid`.

Wirken's client at the issuer is named in the `oidc` block:

```json
"oidc": {
    "issuer": "https://idp.example.com/realms/acme",
    "audience": "wirken-proxy",
    "max_token_lifetime_secs": 900,
    "exchange": {"client_id": "wirken-exchange", "client_secret": "idp-exchange-secret"}
}
```

`client_secret` is a vault entry, bound to the token endpoint's host:

```bash
wirken credentials add idp-exchange-secret --token-exchange idp.example.com
```

A `--token-exchange` binding sends the secret to that endpoint and nowhere
else, not even to `http_request` for the same host
([credentials.md](credentials.md#where-a-credential-may-go)). The secret is
read at each exchange, so a rotation takes effect at the next one.

The token endpoint is the `token_endpoint` of the issuer's discovery
document, which must be on the issuer's origin. It is reached over HTTPS, or
plain HTTP for a loopback issuer, and no redirect is followed. The request
is `grant_type=urn:ietf:params:oauth:grant-type:token-exchange` with the JWT
as `subject_token`, both token types
`urn:ietf:params:oauth:token-type:access_token`, and `audience`, with the
client authenticated by HTTP Basic. The answer must carry a bearer
`access_token` and `expires_in`. One without `expires_in` is refused.

What is held:

- The JWT is sent in the exchange and kept no longer than the request it
  came with.
- The token got for it is held in memory, for the subject and the audience,
  until 30 seconds before it expires. A token that lives less than 30
  seconds is used for its call only. A restart drops every token held.
- Neither token is on any row, in any log line, or on disk.

No call falls back to Wirken's own credential:

- A token Wirken issued, calling a tool of such a server, is refused:
  `exchange_required`. Such a token has no person to exchange for.
- An exchange that fails is refused: `exchange_failed`. That covers no
  `exchange` block in `proxy.json`, a token endpoint that cannot be reached,
  that refuses (its `error` code reaches the client, and what it echoed of
  the request does not), or that answers without a bearer token and an
  expiry.
- Output that carries the token is withheld, and the call answers as failed.

Calls the agent's own model makes to the same server are not exchanged. They
carry the entry's credential, as before.

Each exchange is one `proxy_token_exchanged` row on the caller's lane,
written before the call reaches the gate:

| Field | Meaning |
|---|---|
| `token_id` | The subject's id. |
| `agent_id`, `mcp_session` | The agent and the MCP session of the call. |
| `server`, `audience` | The server and the audience its entry names. |
| `expires_at` | When the exchanged token expires, as the issuer said. |
| `identity` | As on every row of the call. |

A call made with a token still held writes none. An exchange whose row
cannot be written is not used: `record_failed`.

## What it does not do

- It does not issue or refresh a token. It exchanges a caller's JWT only at
  the configured issuer, and only for an MCP server whose signed entry asks
  for it ([Token exchange](#token-exchange)). Every other downstream system
  still sees Wirken's credential, not the caller's. `http_request` and the
  agent's own calls are not exchanged.
- It does not provision users or groups. No SCIM.
- It does not authenticate channel senders. They are admitted by the sender
  allowlist, as before.
- It accepts one issuer.
- A subject hash can be matched to a subject by whoever holds the vault key.
  Removing the key makes the hashes on existing rows unlinkable, and gives
  every subject a new id.
