# Migrating from OpenClaw

## Skills

OpenClaw's 52 bundled skills are `SKILL.md` files — structured markdown with YAML frontmatter. They are not code. Wirken reads the same format.

**To migrate:** Copy your skill directories into `~/.wirken/skills/`.

```bash
cp -r ~/.openclaw/skills/* ~/.wirken/skills/
```

Wirken reads the `name`, `description`, and `metadata.openclaw.requires.bins` fields from the frontmatter. The markdown body is injected verbatim into the agent's system prompt. Skills that require host binaries (e.g., `curl`, `gh`, `tmux`) work if those binaries are installed.

No compilation step. No conversion. The files are identical.

### Code skills

A minority of skills on ClawHub are actual JavaScript/TypeScript that runs as a custom tool. These run in sandboxed Docker or gVisor containers with the same JSON-RPC interface. Set `sandbox_mode` to `"exec-only"` or `"gvisor"` in the org config to enable.

## Credentials

Wirken does not import OpenClaw's plaintext credential files. Credentials must be re-entered.

```bash
wirken setup
```

The setup wizard prompts for your API key and bot tokens. Each credential is encrypted immediately with XChaCha20-Poly1305 and stored in `~/.wirken/vault.db`. The encryption key is derived from the OS keychain (macOS Keychain, Linux Secret Service) or an age-encrypted passphrase file on headless systems.

To add credentials individually after setup:

```bash
wirken channel add telegram    # prompts for bot token
wirken credentials rotate openai-api-key   # rotate an existing key
```

## Configuration

OpenClaw stores configuration in `~/.openclaw/openclaw.json`. Wirken stores:

- Provider config: `~/.wirken/provider.json`
- Credentials: `~/.wirken/vault.db` (encrypted)
- Adapter registry: `~/.wirken/adapters.db`
- Audit log: `~/.wirken/audit.db`
- Sessions: `~/.wirken/sessions.db`
- Permissions: `~/.wirken/permissions.db`

There is no manual config file to edit. All configuration is done through the CLI.

## Agent behavior

OpenClaw's agent uses bootstrap files: `AGENTS.md`, `SOUL.md`, `TOOLS.md`, `USER.md`. Wirken uses a built-in system prompt with skill injection. To customize the agent's behavior, create skills with instructions — the same pattern as OpenClaw's `SKILL.md` files.

## What's different

| OpenClaw | Wirken |
|----------|--------|
| TypeScript, Node.js runtime | Rust, single static binary |
| Single process, all channels in-process | Separate process per channel |
| Plaintext credentials on disk | Encrypted vault, OS keychain |
| No audit trail | Append-only hash-chained audit log |
| `npm install -g openclaw` | `curl -fsSL .../install.sh \| sh` or `cargo install --path crates/cli` |
| `openclaw onboard` | `wirken setup` |
| `openclaw gateway` | `wirken run` |

## What's not yet available

- Voice/TTS
- Mobile companion apps
- Matrix E2EE
