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

## What it does not do

- It does not issue, refresh or exchange a token. A downstream system still
  sees Wirken's credential, not the caller's.
- It does not provision users or groups. No SCIM.
- It does not authenticate channel senders. They are admitted by the sender
  allowlist, as before.
- It accepts one issuer.
- A subject hash can be matched to a subject by whoever holds the vault key.
  Removing the key makes the hashes on existing rows unlinkable, and gives
  every subject a new id.
