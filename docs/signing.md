# Signing

Ed25519 across three independent surfaces: per-instance audit chain-head
signing, per-skill and per-MCP-entry bundle signing, and offline release
signing of the binary distribution. Each has its own keypair, file location
and verification call site. No single key signs across surfaces.

## Chain-head signing

Per-instance signing of `ChainHead` records. The key is generated lazily on
first use, stored owner-only, and never leaves the gateway process.

- **Key material.** Ed25519 raw 32-byte seed at
  `<data_dir>/audit/audit-signing.key` (mode 0o600 on Unix), public counterpart
  at `audit-signing.pub`. `AuditSigningKey::load_or_create` generates on first
  call; later calls re-read. `crates/audit/src/signing.rs:78-110`.
- **Message format, cadence, and what the signature does and does not
  protect against:** [audit-cli.md](audit-cli.md#chain-head-signing).
- **Verification.** `wirken sessions verify` and `wirken audit verify`
  recompute the message bytes from the row's
  `(seq_start, seq_end, prev_hash, hash, schema_version)` tuple and verify with
  `verify_strict` against the recorded `signing_pubkey`.

## Skill signing

The signature covers `SKILL.md` plus `skill.wasm` when present. Wirken does
not run `skill.wasm`. Other sibling files in the directory (`README.md`,
`LICENSE`, fixtures) are out of scope.

**Composite hash.** With `skill.wasm`:
`sha256(SKILL.md_bytes || 0x00 || skill.wasm_bytes)`. Without it:
`sha256(SKILL.md_bytes)`. The null separator is a content-boundary marker, so
a trailing null in `SKILL.md` cannot be confused with a preceding empty wasm.
Adding or removing a `skill.wasm` post-sign shifts the composite and produces
`VerifyResult::Invalid` on the next load. `hash_skill_bundle`,
`crates/gateway/src/skill_registry.rs:247-275`.

**Signing.** `wirken skills sign <dir>` signs the composite hash and writes
the signature as hex to `SKILL.sig` plus the public key to `SKILL.pub`. The
per-author key lives at `<data_dir>/signing-key.hex` (hex Ed25519 seed, mode
0o600), generated on first use and shared with `wirken mcp sign`.

`--key <seed>` signs with that Ed25519 seed file instead of the per-author
key, and never generates one; it is how the bundled set is re-signed with the
project skill-signing key held outside any data directory.

`wirken skills sign --root-key <offline-root-seed> <dir>` additionally binds
the signer key to an operator registry root, writing `SKILL.deleg`, the root's
signature over the signer's public key. The root seed is read from the given
path in the operator's offline signing environment and is never written back.

This is how the bundled set is signed. Each skill directory in the repo
carries a `SKILL.sig`, `SKILL.pub` and `SKILL.deleg` produced this way by the
project skill-signing key under the project registry root, both held offline
like the release key, and the installer writes those files rather than minting
a signature on the host. See [skills.md](skills.md) for the operator side.

**Verification at install.** `wirken skills install` calls
`verify_skill_with_expected_key_and_delegation` on the downloaded bytes against
the registry-supplied `signer_key`, which must carry a `signer_key_delegation`
by the same root the loader uses (below). A download over the
`SKILL.md` size limit (below) is refused. `skill_registry.rs:415-510`.

**Signing the registry index.** `scripts/sign-skills-index.sh`, which runs
`wirken skills sign-index`, signs the index offline under the registry root.
For each entry it checks the entry's signature against the `SKILL.md` in a
local checkout of the registry, writes `signer_key_delegation` and adds
`sha256` where the entry has none; any entry that fails the check refuses the
whole index. `wirken-registry-pubkey.pub` holds the project root from
`skills/REGISTRY-ROOT.pub`; `wirken-mcp-pubkey.pub` ships empty.

**Verification at load.** Every `SkillLoader::load_file` reads `SKILL.md`
once, refusing a file over 1 MiB (`MAX_SKILL_MD_BYTES`) rather than
truncating it. The gate runs over those bytes before any frontmatter parse,
path templating or binary probe, and the parser reads the same bytes, so a
`SKILL.md` replaced on disk after the read never loads. The root is the
operator's (`<data_dir>/registry-root.pub`) when installed, else the compiled
project root:

- `verify_skill_delegated`: the signer (`SKILL.pub`) must be delegated by the
  root via `SKILL.deleg`, and the bundle signature must verify under that
  signer. A self-signed-only bundle and an unsigned bundle are refused.
- A bundled preset skill whose `SKILL.md` matches the copy compiled into the
  binary byte for byte loads without signature files.
- A skill the running process staged, such as the skills a Lyrik run stages,
  is delegated under a root the process generates in memory, and loads in that
  process only.
- In a build without a compiled root, the gate falls back to
  `verify_skill_self_signed`, and `WIRKEN_ALLOW_UNSIGNED_SKILLS=1` admits a
  bundle with no signature.

Source: `crates/agent/src/skill.rs` (`verify_skill_signature`,
`verify_skill_signature_with_root`), `skill_registry.rs` (`read_skill_md`,
`verify_skill_self_signed`, `verify_skill_delegated`, `load_registry_root`).

**Operator registry root.** `wirken skills trust-root <pubkey-hex>` installs an
operator-controlled Ed25519 root public key at `<data_dir>/registry-root.pub`.
The file is integrity-sensitive, not secret: mode 0o644, so a non-owner
process cannot replace the anchor while any reader may verify against it. This
is runtime operator state and replaces the compiled root. The matching root **private** key never ships
and never lands on the gateway host; it signs per-skill delegations offline.
The gate resolves the root from the same `default_data_dir()` the running
gateway uses, so the two never look in different directories.

**Absent versus corrupt root.** No root file means the compiled root. A root
file present but unparseable fails closed: it refuses every skill and surfaces
as `AgentError::RegistryRootUnusable` at error level.

**Revocation and containment.** The root file is writable by anyone with
gateway-UID write, so the file is not the anchor: the offline private key is.
Deleting it falls back to the compiled project root; it grants nothing.
Replacing it with a root the attacker holds lets that attacker's delegated
skills load, which needs gateway-UID write on a host where they already hold
it.

## MCP entry signing

`mcp.json` entries can carry an Ed25519 signature over the entry's canonical
hash, mirroring skills. `wirken mcp sign <server>` signs one entry against
`<data_dir>/signing-key.hex`; `wirken mcp verify [<server>]` reports
`valid` / `invalid` / `unsigned` per entry. See [mcp.md](mcp.md#signing-mcp-entries)
for the canonical hash layout and what the signature attests.

## Release signing

Offline maintainer signing of release artifacts. The private key is held
outside the repo tree; the public key is embedded in `install.sh` and pinned
in `KEYS` (OpenSSH allowed_signers format), with the fingerprint recorded in
`SECURITY.md`. Verification needs only OpenSSH 8.1+.

**What gets signed.** `checksums.sha256`, signed with `ssh-keygen -Y sign` to
produce `checksums.sha256.sig`. The release build produces both alongside the
platform binaries on every `v*` tag.

**Verification at install.** `install.sh` fetches both, verifies the signature
with `ssh-keygen -Y verify` against the embedded key, then verifies the
binary's SHA-256 against the signed checksums. Every failure path is
fail-closed: missing signature, missing checksum, mismatched digest, or a
machine without `sha256sum`/`shasum` aborts the install. A forged binary
without a matching checksum fails the second step; a forged checksums file
without the private key fails the first. The documented opt-out is
`WIRKEN_ALLOW_UNVERIFIED=1`, install-time only.

### Verify a release by hand

Paste-ready, and does not trust `install.sh` or the current `main`. Pinning
`KEYS` to a specific commit means even a compromised `main` cannot shift the
trust anchor under you.

```bash
TAG=v1.22.0                                   # release to verify
BINARY=wirken-x86_64-unknown-linux-musl       # your platform
PINNED_COMMIT=<40-char-sha-of-an-audited-commit>

mkdir /tmp/wirken-verify && cd /tmp/wirken-verify

curl -fsSLO "https://github.com/gebruder/wirken/releases/download/$TAG/$BINARY"
curl -fsSLO "https://github.com/gebruder/wirken/releases/download/$TAG/checksums.sha256"
curl -fsSLO "https://github.com/gebruder/wirken/releases/download/$TAG/checksums.sha256.sig"
curl -fsSL  "https://raw.githubusercontent.com/gebruder/wirken/$PINNED_COMMIT/KEYS" -o KEYS

ssh-keygen -Y verify -f KEYS -I releases@gebruder.ottenheimer.app \
    -n file -s checksums.sha256.sig < checksums.sha256

grep " $BINARY\$" checksums.sha256 | sha256sum -c -
```

```
Good "file" signature for releases@gebruder.ottenheimer.app with ED25519 key SHA256:tzlfNHy4G1KIsmAR+cM3MGwVndheh2ak/usA6rw7SuE
wirken-x86_64-unknown-linux-musl: OK
```

Cross-check that fingerprint against [SECURITY.md](../SECURITY.md) and the
`KEYS` comments at the pinned commit. Set `PINNED_COMMIT` to a commit you
audited, the one you originally installed from, or the one named in a security
advisory; pulling `KEYS` from `main` is fine for casual verification and
pinning is for the threat model where `main` itself might be suspect.

### Build provenance

A second, independent trust root sits beside the offline signature. Releases
publish `wirken.intoto.jsonl`, a SLSA Build L3 provenance attestation signed
through the GitHub OIDC-rooted Sigstore chain and recorded in a public
transparency log. Where the Ed25519 signature answers "the maintainer vouches
for these bytes", the provenance answers "this exact workflow, on this commit,
in this runner, produced them". They compose; neither replaces the other, and
both are standalone release assets you can mirror independently of the
attestations API.

```bash
curl -fsSLO "https://github.com/gebruder/wirken/releases/download/$TAG/wirken.intoto.jsonl"

slsa-verifier verify-artifact "$BINARY" \
    --provenance-path wirken.intoto.jsonl \
    --source-uri github.com/gebruder/wirken \
    --source-tag "$TAG"
```

`PASSED: SLSA verification passed` confirms the binary was built by the pinned
release workflow at that tag. [`slsa-verifier`](https://github.com/slsa-framework/slsa-verifier)
is a single binary and deliberately not a dependency of `install.sh`. Releases
cut before the provenance workflow landed carry only the Ed25519 signature,
and the curl for `wirken.intoto.jsonl` 404s on those.

**Anchor rotation** swaps the trust anchor in one commit and immediately cuts a
new release signed with the new key. The maintainer runbook is
[release-process.md](release-process.md).

## Source references

- Chain-head signing: `crates/audit/src/signing.rs:38-208`.
- Skill bundle signing: `crates/gateway/src/skill_registry.rs:63-502`.
- Skill load-time verification: `crates/agent/src/skill.rs:149`, `:510-603`.
- MCP entry hashing: `crates/mcp-proxy/src/mcp_signing.rs::hash_mcp_entry`.
