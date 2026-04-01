# Troubleshooting

## wirken setup fails

**"Failed to open credential store"**

The vault database or keychain is inaccessible. On Linux, this usually means the Secret Service (GNOME Keyring or KDE Wallet) is not running. Wirken falls back to an age-encrypted file keychain and prompts for a passphrase.

If you're on a headless server, the passphrase prompt is expected. Enter a passphrase you'll remember.

**"Homeserver URL must use HTTPS"**

The Matrix adapter requires HTTPS for all non-localhost homeservers. Use `https://` in the homeserver URL.

## wirken run fails

**"No AI provider configured"**

Run `wirken setup` first. This creates `~/.wirken/provider.json`.

**"Failed to bind UDS"**

The socket file already exists from a previous run. Either the gateway is already running, or it crashed without cleanup. Delete the socket:

```bash
rm ~/.wirken/sockets/gateway.sock
wirken run
```

**"Adapter exited"**

An adapter process crashed. Check the logs with `RUST_LOG=wirken=debug wirken run`. Common causes:
- Invalid bot token (re-enter with `wirken channel add <channel>`)
- Network connectivity (the adapter can't reach the platform API)
- Token expired (rotate with `wirken credentials rotate <name>`)

## Agent doesn't respond

**On a messaging channel:**
- In group channels, the bot only responds when mentioned by name
- Check that the channel is routed to an agent: the startup output shows `Route: <channel> -> agent:<id>`
- Check the audit log: `wirken audit log --channel <channel> -n 10`

**With `wirken ask`:**
- Check that the API key is valid: `wirken credentials list` shows the credential metadata
- Check provider connectivity: `wirken doctor`
- Try with debug logging: `RUST_LOG=wirken=debug wirken ask -m "hello"`

**With Ollama:**
- Small local models (e.g., llama3.2) may hallucinate tool calls, causing the agent to loop without producing a response. Tools are disabled by default for Ollama to avoid this.
- Non-streaming requests (used by channel adapters) wait for the full response before replying. This can take 10-30 seconds depending on your hardware. WebChat uses streaming and feels faster.
- Verify Ollama is running: the gateway prints the detected version at startup (e.g., `Ollama version: 0.19.0`).

## Vault passphrase mismatch

**"decryption failed: aead::Error"**

Credentials were stored with a different vault passphrase than the one currently being used. This happens when `wirken setup`, `wirken channel add`, and `wirken run` are run with different passphrases.

Fix: re-add the affected channel or credential using the same passphrase you use for `wirken run`:

```bash
wirken channel remove slack
wirken channel add slack
```

Use the same passphrase consistently across all commands.

## Tool execution fails

**"access denied: path is outside the workspace"**

File operations are confined to the agent's workspace directory (`~/.wirken/workspace/` by default). The agent cannot read or write files outside this boundary.

**"Command timed out after 300s"**

Shell commands have a 5-minute timeout. The process is killed automatically. If you need longer-running commands, consider running them in tmux via the tmux skill.

## Credential issues

**"Expired" error when retrieving a credential**

The credential has passed its `expires_at` date. Rotate it:

```bash
wirken credentials rotate <name>
```

**"Rotation due" warning**

The credential is past its `rotation_due_at` date but still functional. Rotate it at your convenience.

**Lost vault passphrase**

If you're using the age-encrypted file keychain (headless systems) and forget the passphrase, you'll need to re-enter all credentials:

```bash
rm ~/.wirken/vault.db ~/.wirken/age-key.enc ~/.wirken/age-salt
wirken setup
```

## MCP server won't start

**"spawn 'npx': No such file or directory"**

Node.js is not installed or not in PATH. Install Node.js 18+ and ensure `npx` is available.

**"MCP server timed out after 30s"**

The server didn't respond to the `initialize` handshake within 30 seconds. Check that the command runs successfully on its own:

```bash
npx -y @modelcontextprotocol/server-filesystem /tmp
```

## SIEM forwarding

**"SIEM forward failed"**

Check the endpoint URL and API key in `~/.wirken/siem.json`. Forwarding errors are logged as warnings and never block the audit pipeline. The local SQLite audit log continues to work regardless.

## Docker sandbox

**"Docker connect: error"**

Docker is not running or the current user doesn't have access. Check:

```bash
docker info
```

If Docker is running but the user lacks permission, add them to the docker group:

```bash
sudo usermod -aG docker $USER
```

Then log out and back in.

## Debug logging

For detailed output, set the `RUST_LOG` environment variable:

```bash
RUST_LOG=wirken=debug wirken run
RUST_LOG=wirken=trace wirken run    # very verbose
```

## Diagnostics

```bash
wirken doctor
```

This checks provider config, vault access, adapter registration, and reports any issues.

## Reporting bugs

Check the [GitHub issues](https://github.com/gebruder/wirken/issues). If your issue isn't listed, open a new one with:
- Wirken version (`wirken --version`)
- OS and architecture
- Steps to reproduce
- Relevant log output (`RUST_LOG=wirken=debug`)

For security vulnerabilities, see [SECURITY.md](../SECURITY.md).
