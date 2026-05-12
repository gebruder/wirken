# Skill authoring

Wirken skills are operator-installable behavior bundles: a `SKILL.md` file with YAML frontmatter, optionally accompanied by a `skill.wasm` module and a `SKILL.sig` / `SKILL.pub` pair. This page documents the on-disk layout, the frontmatter rules the loader enforces, and the signing contract.

## Required structure

A skill is a directory whose basename is the skill name. The minimal layout:

```
my-skill/
├── SKILL.md     (required)
├── SKILL.sig    (recommended; required for signed installs)
├── SKILL.pub    (recommended; pairs with SKILL.sig)
└── skill.wasm   (optional; pulled in via metadata.wirken.requires.wasm)
```

`SKILL.md` is YAML frontmatter followed by Markdown body. The body is what the LLM reads as the skill's instructions; the frontmatter is what the loader reads to validate identity and capability.

## Frontmatter rules

### `name` (optional but auditable)

When present, must agree with the parent directory basename. When omitted, the directory basename becomes the skill name. Either way, the loader runs the same validation:

- Lowercase ASCII letters, digits, hyphens only: regex `^[a-z][a-z0-9-]{0,63}$`.
- Must start with a lowercase letter (digit or hyphen prefix rejected so a skill name can't be confused with a numeric flag in CLI rendering).
- Length 1 to 64 characters.
- No uppercase, underscores, dots, slashes, or non-ASCII (one token on every filesystem and in every shell).

Source: `crates/agent/src/skill.rs:375-400` (`validate_name`).

### `description` (required)

Required, non-empty, at most 1024 characters. Counted by Unicode scalar, not bytes.

Source: `crates/agent/src/skill.rs:404-418` (`validate_description`).

### `permissions` (optional)

When omitted, the loader applies `PermissionProfile::default()`: least-privilege deny-all on every axis (empty `tools`, deny-all `egress`, empty `filesystem` read/write paths, empty `inference.allow`). A skill without a `permissions` block loads cleanly but cannot do anything beyond emitting text through the prompt; the operator opts into capability by writing the block.

When present, the block must conform to `PermissionProfile` as defined in `crates/agent/src/skill_perms.rs:35-100`. Four axes: `tools`, `egress`, `filesystem`, `inference`. Wildcard `"*"` is supported on `tools`, `egress.domains`, and `inference.allow`; filesystem wildcards are rejected (cap-std workspace confinement is the outer bound and `"*"` for paths is meaningless inside it).

Source: `crates/agent/src/skill.rs:199-212` (loader fallback), `crates/agent/src/skill_perms.rs:1-17` (axis description).

### `metadata.wirken.*` (optional)

Currently used for `metadata.wirken.requires.bins` (a list of host binaries the skill needs on `PATH`). The loader checks each via `which`; if any are missing, the skill is marked `available: false` and the agent will not expose it to the LLM, but the bundle is still loaded (so `wirken skills list` shows it). Source: `crates/agent/src/skill.rs:338-356`.

### `metadata.openclaw.*` (dropped in 1.4.0)

Skills carrying `metadata.openclaw.*` continue to load (no error), but the field is silently ignored. The `metadata.wirken.*` key is the only recognized location. Skills authored against the deprecated alias can be migrated with `wirken skills migrate`. Source: `crates/agent/src/skill.rs:332-337`.

## Signature at load

Every `SkillLoader::load_file` call invokes `verify_skill_signature` against the on-disk `SKILL.sig` and `SKILL.pub`:

- **Signed bundle.** `SKILL.sig` and `SKILL.pub` present, signature verifies against the composite hash: load proceeds.
- **Unsigned bundle.** No `SKILL.sig` / `SKILL.pub` pair: load refused unless `WIRKEN_ALLOW_UNSIGNED_SKILLS=1` is set. With the bypass, the loader emits a warn-on-stderr message identifying the bundle and proceeds. An audit row records the bypass.
- **Bundle with invalid signature.** `SKILL.sig` present but does not verify against the bundle's current contents: load refused. The `WIRKEN_ALLOW_UNSIGNED_SKILLS` bypass does not cover this case; an invalid signature is always a hard fail.

Source: `crates/agent/src/skill.rs:218` (verify call), `crates/agent/src/skill.rs:469-503` (`verify_skill_signature`).

## Composite signature scope

The signature covers `SKILL.md` plus `skill.wasm` when present. Other sibling files in the skill directory (`README.md`, `LICENSE`, fixtures, etc.) are not in scope.

Composite hash layout:

- With `skill.wasm`: `sha256(SKILL.md_bytes || 0x00 || skill.wasm_bytes)`.
- Without `skill.wasm`: `sha256(SKILL.md_bytes)`.

The null-byte separator is a content-boundary marker: a trailing null in `SKILL.md` cannot be confused with a preceding empty wasm. Adding a `skill.wasm` post-sign or removing one post-sign both shift the composite and produce `VerifyResult::Invalid` on the next load.

Source: `crates/gateway/src/skill_registry.rs:109-140` (`hash_skill_bundle`).

## Frontmatter envelope check

The loader refuses any skill whose name, description, or body contains the literal tokens `BEGIN UNTRUSTED SKILL` or `END UNTRUSTED SKILL`. These mark the trust boundary in the system prompt that wraps third-party skills; allowing a skill to carry them would let a hostile author emit a closing envelope marker at the boundary heading. The per-build nonce already defeats literal-marker collisions in the rendered prompt, but the load-time refusal is the simpler story than scrubbing inside `build_prompt`.

Source: `crates/agent/src/skill.rs:159-173`, `crates/agent/src/skill.rs:427-`.

## Source references

- Loader: `crates/agent/src/skill.rs:125-503`.
- Frontmatter validation: `crates/agent/src/skill.rs:375-418`.
- Permission profile: `crates/agent/src/skill_perms.rs:1-100`.
- Composite signature: `crates/gateway/src/skill_registry.rs:101-172`.
- Signing surfaces overview: [signing.md](signing.md).
