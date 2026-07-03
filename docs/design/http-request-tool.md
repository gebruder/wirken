# Design: the `http_request` built-in tool

Status: implemented on branch `http-tool`. This note is the spec; the
tests in `crates/agent/src/http_tool_tests.rs` encode every decision
below. Where a claim here is not yet enforced in code it is written as
a **Limitation**, not a feature.

`http_request` is a built-in agent tool that lets a skill make a scoped
outbound HTTPS request and attach a vault-held credential the model
never sees. It exists so a read-only integration skill can call a REST
API with an operator-provisioned token, without the token ever entering
model context, tool output, logs, or the audit payload. The motivating
case is a staff or asset lookup against an internal system such as
TeamDynamix.

It is deliberately narrower than `curl`-under-`exec`: it is egress-
allowlist-mediated (unlike the shell sink, see `egress.rs:19-41`), it
injects credentials host-side, and it cannot reach a host the skill did
not allowlist.

## Tool surface

Registered as `http_request` in `ToolRegistry` (`crates/agent/src/tool.rs`).
Parameters (JSON schema on the `ToolDef`):

| field | type | notes |
|---|---|---|
| `method` | string | `GET`, `HEAD`, or `POST`. No `PUT`/`PATCH`/`DELETE`. |
| `url` | string | Absolute `https://` URL. |
| `headers` | object (string→string) | Optional. `Authorization`/`Proxy-Authorization` are refused (see credential flow). |
| `body` | string | Optional. Sent for `POST` only. |
| `credential` | string | Optional. Names a vault slot the skill declared in `permissions.credentials.allow`. |
| `timeout_ms` | integer | Optional. Default 30000, capped at 60000. |

Result (the `ToolResult.output`, a JSON string):
`{"status": <u16>, "headers": {..server headers minus auth..}, "body": <string>, "truncated": <bool>}`.
`success` is true iff the HTTP status is 2xx; a 4xx/5xx still returns
status + headers + body so the model can react.

## Credential flow

1. The model names a vault slot by string in `credential`. It never
   supplies a secret value; it cannot, the vault holds it.
2. `permissions.credentials.allow` (new, see below) is the skill's
   declared set of slots. A tool call naming an undeclared slot is
   refused **at the gate layer** (`gate_credential`, alongside the
   existing `gate_tool` `tools.allow` check), before dispatch and
   before any resolution.
3. After the gate accepts, the handler resolves the slot host-side
   through an injected `CredentialResolver` (implemented over
   `CredentialStore::retrieve`, `crates/vault/src/store.rs`). The
   resolved secret is a `ResolvedSecret` newtype with no `Debug`,
   `Display`, `Serialize`, or `Clone` (mirrors `VaultSecret`).
4. The handler injects it as exactly one header,
   `Authorization: Bearer <secret>`, on the outbound request, then
   drops it. The secret is never stored on a struct, never formatted
   into a string that is returned, logged, or audited, and never placed
   in a subprocess environment (there is no subprocess).

Redaction is enforced on every serialization path: the returned
`headers` map excludes any `Authorization`/`Proxy-Authorization`; the
audit event carries the slot **name** only (the `LlmRequest.credential_id`
convention); error messages carry the host/path/status, never the
secret. See **Does NOT protect against** for the one echo path we
cannot scrub.

### Model-supplied auth is refused

If the model puts an `Authorization` or `Proxy-Authorization` header in
`headers`, the call is **refused** (not silently stripped) with an error
result telling it to use the `credential` field. Only the vault-resolved
credential ever sets that header; a model attempt to set it fails loudly
and does not win.

## Credential-host binding (the control that makes this safe)

This is the load-bearing control, and without it the tool would be
unsafe. Absent binding, authorization would be the skill's own
frontmatter: a phished skill update pairing `credentials.allow:
[tdx-api]` with `egress.domains: [attacker.example]` would exfiltrate
the Bearer token at Tier 1, no prompt. So a credential is bound to
permitted hosts **in the vault, by the operator**, and the binding is
enforced host-side at injection:

```bash
wirken credential add records-api --host records.example.org
```

`http_request` resolves the credential through the `CredentialResolver`,
which checks the request's host against the credential's stored
`allowed_hosts` (exact, case-insensitive) before returning the secret.
A request to any other host is refused and the secret is never injected,
**regardless of what the skill's `egress.domains` allows**. Deny by
default: a credential with no `--host` binding is unusable by
`http_request` at all. The effective destination set is the
intersection of the operator's credential binding and the skill's egress
allowlist; a skill can only ever narrow it, never widen it. Enforced in
`CredentialMetadata::permits_host` (`crates/vault/src/store.rs`) and the
`VaultCredentialResolver` (`crates/cli/src/commands/run.rs`).

## Credential scoping (new permissions block)

`PermissionsBlock` (`crates/agent/src/skill_perms.rs`) gains a
`credentials` sub-block with `deny_unknown_fields`, following the
`tools` shape exactly:

```yaml
permissions:
  credentials:
    allow: [tdx-web-services-key]
```

Resolved to `CredentialsPolicy { allow: AllowSet }` on `PermissionProfile`;
`EffectiveProfile::allows_credential` mirrors `allows_tool`; the merge
path unions the allow-set across a skill set like every other axis.
Deny-by-default: a skill with no `credentials` block may name no slot.

## POST carve-out (new permissions field)

GET and HEAD need no path declaration. POST is refused unless the
request's `(host, path)` matches an entry the skill declared in
`permissions.http.post_paths` (new sub-block, `deny_unknown_fields`):

```yaml
permissions:
  http:
    post_paths: ["https://records.example.org/api/assets/search"]
```

Each entry is an absolute `https://` URL; the match is host + path
exact, query string ignored. This is enforced at the gate layer
(`check_http_request_or_deny` in `runtime.rs`), so a POST to any
undeclared path on an allowlisted host is refused, not merely
un-routed. Some REST APIs expose search as a POST; this is the only
write-shaped verb the tool permits, and only to a pre-declared endpoint.

## Egress

The request is issued through `EgressClient` (`crates/agent/src/egress.rs`),
so `permissions.egress` (mode `allowlist`, `domains: [...]`) binds this
tool's traffic exactly as it binds `web_search`. Deny by default;
per-skill allowlist. A request to a host not on the allowlist returns
`EgressDenied`, which the runtime records as `SkillPermissionDenied`
(host axis) and returns to the model as a failed result. This is a
**refusal, not a prompt** (see tiering). The boundary comment at
`egress.rs:19-41` is updated: `http_request` is the third egress-
mediated built-in, joining `web_search` and `generate_image`.

## Host-matching semantics

The allowlist and the POST/URL checks match the **parsed host
component** (`url::Url::host_str`), never the raw string. Concretely:

- **Userinfo is refused.** `https://allowed.example@evil.example/`
  parses to host `evil.example`; any URL carrying a userinfo component
  is rejected outright before the egress check, so the `@` trick can
  neither smuggle a host past the allowlist nor leak a value.
- **Scheme must be `https`.** `http`, `file`, `ftp`, etc. are refused.
- **IP-literal hosts are refused.** A host that parses as an IPv4/IPv6
  literal is rejected, blocking direct SSRF to `169.254.169.254`,
  loopback, and private ranges regardless of the allowlist.
- **Exact host, no implicit subdomain.** `allowed.example` does not
  match `sub.allowed.example`. Subdomains must be listed (the egress
  allowlist's own `*.` wildcard entry, `skill_perms.rs host_matches`,
  is the only wildcard path and is opt-in).
- **Port-agnostic.** The match is on host only; allowlisting a host
  authorizes it on any port over https (`allowed.example:8443` matches
  `allowed.example`). So a different service on another port of the same
  host is in scope, for both the egress allowlist and the credential
  binding. Port-scoping is not supported (see Limitations).

## Redirects

Redirect following is **disabled entirely** (`redirect::Policy::none()`
on a dedicated request client). A 3xx is returned to the agent as-is
(status + headers minus auth + body); nothing is followed, so the auth
header is never sent to a redirect target. If the agent wants the
target it issues a fresh `http_request`, which re-runs the full gate
(egress allowlist, credential scope, method/path rules). This is the
provable option: there is no cross-origin auth-forwarding path to
reason about because there is no following.

## Tiering

`http_request` maps to a new `Action::HttpRequest` classified as
**Tier 1** (`crates/gateway/src/permissions.rs`): the interactive
approval flow adds no prompt. The authorization is not a prompt; it is
the skill's permissions block, evaluated as hard gates that **refuse**:

- `tools.allow` must contain `http_request` (`gate_tool`).
- `credentials.allow` must contain the named slot (`gate_credential`).
- POST path must be in `http.post_paths`.
- the host must be on `egress.domains` (enforced in-flight by
  `EgressClient`).

Anything failing these is refused, never escalated to a Tier-3 prompt,
and there is no global bypass: a skill that does not opt in via its
permissions block cannot call the tool or reach a host. Pre-
authorization is per skill, per host. This is the "allowlisted read-
only requests must not prompt per call" requirement: an allowlisted GET
runs with no prompt; a non-allowlisted request is refused, not prompted.

This is a deliberate trade: authorization moved from human-in-the-loop
(a Tier-3 prompt on every call) to install-time policy. Install-time
policy trusts the operator's signed skill and, for where a secret may
travel, the operator's credential-host binding rather than the skill
author. Bypassing the pre-existing Tier-3 `CredentialAccess` action was
required to meet the no-prompt goal; the credential-host binding is what
replaces the prompt as the control on secret destination.

## Response handling

- **Body cap:** 1 MiB (`HTTP_TOOL_BODY_CAP`). On overflow the body is
  **truncated** at the cap and `truncated: true` is set (distinct from
  the 32 MiB `read_capped` used by `web_search`, which errors; an API
  lookup response returned into model context wants a tighter,
  truncating cap).
- **Timeouts are mandatory:** per-request total timeout from
  `timeout_ms` (default 30s, cap 60s) plus a 10s connect timeout on the
  client. A hung connection hits the timeout and returns an error
  result, not a prompt.
- Returns status, headers (minus auth), body, truncation flag.

## Audit

Every completed `http_request` lands one `SessionEvent::HttpRequest`
row in the per-session hash chain (`crates/audit/src/session_log.rs`),
carrying `method`, `host`, `path`, `status`, the credential **name**
(never value), `truncated`, and `agent_id`. The chain hashes the
payload, so the row links and the chain still verifies afterward. A
request refused before send (bad gate, egress deny) is recorded by the
existing `SkillPermissionDenied` machinery instead; `HttpRequest` is
the completed-request row.

## What this tool does NOT protect against

Stated in the same plain terms as the egress boundary comment
(`egress.rs:19-41`):

- **DNS rebinding / internal-IP resolution.** The allowlist is
  name-based. An allowlisted hostname that resolves to `169.254.169.254`
  or a private address is not blocked; we refuse IP-literal URLs but do
  not re-check the resolved address of an allowlisted name. Operators
  wanting hard SSRF control still need network-namespace / firewall
  egress rules, as the egress boundary comment already states.
- **A server echoing the secret.** We redact the request auth header
  from every result and audit row, but if the allowlisted endpoint
  reflects the injected `Authorization` value back in its response
  body, that body is returned to the model and we cannot detect it.
  Allowlisting a host trusts that host with the credential.
- **Secret-in-process-memory.** The credential is decrypted in the
  gateway process to set the header. A compromised gateway process can
  read it; that is the same trust boundary as the vault itself, not a
  boundary this tool adds.
- **Operator egress proxy.** The request client honors `HTTPS_PROXY` /
  `HTTP_PROXY`, so where an operator forces egress through a proxy the
  credential-bearing request traverses it. This is intended: enterprises
  legitimately route egress through proxies. The credential stays
  TLS-protected end-to-end to the bound host, the allowlist and host
  binding are still enforced on the target host, and a proxy could read
  the credential only with an operator-trusted MITM certificate, which
  is the operator's own trust decision, not a boundary this tool adds.
- **Request-body content.** A model-supplied POST body to a declared
  search path is sent as-is; the tool does not inspect it for
  exfiltration. The `post_paths` declaration trusts the endpoint.
- **Port scoping.** Allowlisting a host authorizes all ports on it over
  https (Limitation above).
- **An over-broad or later-hostile binding.** The credential-host
  binding is only as good as the operator's host list. Binding a
  credential to a host that is too broad, or that later becomes hostile,
  still sends the secret there. The binding stops a skill from widening
  the destination; it does not second-guess the operator's own choice.

## Limitations (not yet enforced as features)

- Auth scheme is fixed to `Authorization: Bearer <secret>`. Custom
  header names / schemes (`X-Api-Key`, basic auth) are not supported.
- Port-scoped and resolved-IP allowlisting are not supported (above).
- Credential-host matching is exact per host; there is no `*.` wildcard
  for credential bindings (the egress allowlist has one, but a credential
  binding does not, by choice).
- Production CLI wiring is in place: the gateway opens the vault at
  startup and attaches a `VaultCredentialResolver` to the agent factory,
  so every waked agent resolves host-bound credentials. If the vault is
  unavailable the resolver is absent and a credentialed `http_request`
  refuses rather than proceeds.
