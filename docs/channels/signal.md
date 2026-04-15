# Signal

```bash
wirken channel add signal
```

Signal is different from every other wirken channel. There is no bot API: you connect by running [signal-cli](https://github.com/AsamK/signal-cli) as a local JSON-RPC daemon and pointing wirken at it. That daemon acts as a real Signal client, under your identity. This page documents how to set it up **and** the exposure that comes with it, so you can decide whether to run it and how to harden it.

## What you get

- Inbound: wirken polls signal-cli every second and forwards incoming Signal messages (DMs and groups) to the gateway as normal channel messages.
- Outbound: the agent's replies are sent back through signal-cli, which delivers them as if you typed them from your phone.
- Works with 1:1 DMs and Signal groups. Non-text messages (typing indicators, reactions, stickers) are dropped.

## Setup

### 1. Install signal-cli

signal-cli ships two Linux builds. The native (GraalVM-compiled) build is usually the right choice because it has no JRE dependency:

```bash
# Download the native build (check https://github.com/AsamK/signal-cli/releases for latest)
curl -sSLO https://github.com/AsamK/signal-cli/releases/download/v0.14.2/signal-cli-0.14.2-Linux-native.tar.gz
tar -xzf signal-cli-0.14.2-Linux-native.tar.gz -C ~/.local/bin/
chmod +x ~/.local/bin/signal-cli
signal-cli --version
```

If you prefer the JVM build, you'll need a matching Java version. Check the release notes: signal-cli 0.14.2 requires Java 25.

### 2. Link signal-cli to your Signal account

Two options:

**Link as a secondary device (recommended).** Your phone stays primary; signal-cli becomes a linked device like Signal Desktop. No SMS, no new phone number, and your existing Signal install keeps working.

```bash
signal-cli link -n "wirken"
```

This prints a `tsdevice://...` URL. Open Signal on your phone → Settings → Linked devices → + → scan or paste the URL. (To scan you'll need to render the URL as a QR code with something like `qrencode`.)

Caveats of linked-device mode:
- The linked device only sees messages that arrive *after* the link. Prior history stays on your phone.
- Group metadata and contacts sync in the background and can take a few minutes.
- If you unlink from your phone, wirken's adapter stops receiving messages until you re-link.

**Register a new phone number.** Only do this if you want a dedicated number for the bot. signal-cli becomes the primary device for that number, which kicks any existing Signal install on that number offline and requires SMS/voice CAPTCHA verification. See the [signal-cli wiki](https://github.com/AsamK/signal-cli/wiki/Quickstart) for the full flow.

### 3. Run the daemon bound to localhost

**Always bind the HTTP endpoint to `127.0.0.1`**, never `0.0.0.0`. The daemon has no authentication; anything that can reach the port can send messages as you.

```bash
signal-cli -a +15551234567 daemon --http 127.0.0.1:8080
```

Leave that running in a terminal or under a supervisor (systemd user unit, tmux, etc.). Verify it's responsive:

```bash
curl -s http://127.0.0.1:8080/api/v1/rpc \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"version","id":1}'
```

### 4. Register with wirken

```bash
wirken channel add signal
```

You'll be prompted for:

- **Registered phone number**: the E.164 number you linked or registered.
- **signal-cli JSON-RPC endpoint**: defaults to `http://127.0.0.1:8080/api/v1/rpc`.
- **Allowed senders (comma-separated)**: **required**. See the next section.

### 5. Configure the sender allowlist

The Signal adapter is fail-closed: an empty allowlist drops every inbound message. Setup prompts you for the initial list, and you can edit it later:

```bash
wirken vault set signal-allowed-senders "+15551234567,+15559876543,group-abc-xyz="
```

Entries are matched against the inbound message's conversation:

- **1:1 DMs**: the sender's E.164 phone number must be in the list.
- **Group messages**: the Signal group ID must be in the list. The sender inside the group is not checked; group membership is your access control.

To find a group's ID:

```bash
signal-cli -a +15551234567 listGroups
```

If you change the allowlist, restart the signal adapter (`wirken adapter signal`) for it to pick up the new values.

## Signal-specific exposure

The project-wide agent controls (permission tiers, workspace path confinement, injection detection, sandboxing, audit trail) are described in [`docs/security-properties.md`](../security-properties.md). Read that first. This section only covers what is different or additional for the Signal adapter.

### The allowlist is the only thing between Signal contacts and the LLM

There is no per-sender auth in Signal; anyone who has your linked number can send you a message. The allowlist is therefore the entire perimeter, and the adapter fails closed on an empty list. Everything past the allowlist is inside the trust boundary: the LLM sees the message, the tool registry is in scope, and the same permission tiers that apply to every other channel apply here. If you add someone to the allowlist, you are trusting them with whatever Tier 1 actions the agent can perform unprompted, plus any Tier 2 approvals you have previously granted (see next point).

### Pre-existing Tier 2 approvals apply to Signal messages too

A Tier 2 approval is recorded per-agent, not per-channel. If you have already approved `exec` of, say, `bash` for the default agent (perhaps through an earlier Telegram or CLI session), then a message from an allowlisted Signal sender that triggers `exec bash ...` will run without prompting. Before putting the Signal adapter in front of an agent, review `wirken permission list <agent_id>` and revoke grants you are not comfortable exposing to Signal traffic.

### Prompt-injection detection is monitoring, not prevention

The gateway's `InjectionDetector` (see `docs/security-properties.md` → MEASURE 2.6) scans every inbound Signal message for role-switching, instruction overrides, base64-encoded shell, tool-call injection, and system-prompt extraction. When it fires, it annotates the `message.inbound` audit event and emits a separate `message.threat_flagged` event for SIEM. It does **not** block the message, rewrite it, add a warning to the LLM turn, or gate tool execution on the threat level. Tracking higher-confidence responses to Critical-severity flags is an open backlog item.

### signal-cli daemon HTTP endpoint has no authentication

The signal-cli JSON-RPC HTTP endpoint is not authenticated. Any local process on the host can `POST` to it and send Signal messages as you. Mitigations:

- Bind to `127.0.0.1`, never `0.0.0.0`.
- Run signal-cli as a dedicated user on multi-user hosts.
- Consider restricting the port to your UID with `iptables`/`nftables` owner matches.
- signal-cli also supports a Unix-socket transport (`--socket` / DBus). The wirken adapter speaks HTTP today; moving to a local socket with filesystem permissions is a planned hardening.

### signal-cli credential storage

Linking produces an account state directory at `~/.local/share/signal-cli/data/` containing your Signal protocol keys in cleartext. Whoever holds that directory can impersonate you on Signal indefinitely, until you manually unlink the device from your phone.

- Back it up only to an encrypted location. File-sync tools (Dropbox, Google Drive, rsync) that pick up `~/.local/share/signal-cli/` effectively hand over your Signal identity.
- If you suspect compromise, open Signal on your phone → Settings → Linked devices → remove the wirken device. That rotates the relevant keys.
- `chmod 700 ~/.local/share/signal-cli/` is a reasonable baseline.

### What Signal's crypto does and doesn't buy you

Signal's end-to-end encryption is not what fails here. An allowlisted message arrives authenticated and decrypted; its text is placed into an LLM prompt; the LLM may act on attacker-controlled instructions. The transport is cryptographically sound; the application layer above it is a classic prompt-injection surface. The allowlist, the permission tiers, and the injection detector's audit trail are what bound the blast radius.

## Known limitations

- **Inbound polling interval is 1 second.** Latency between message receipt and agent response is ≥1s plus LLM time. Not a fit for low-latency chat.
- **No typing indicators, reactions, or read receipts.** We drop everything except text messages.
- **Approval is coarse.** Tier 2 shell approvals are keyed on the first token of the command. Finer-grained patterns are not yet supported.
- **No rate limiting on the adapter.** An allowlisted sender spamming messages will spam the LLM and your API bill. If you expose this to more than a handful of trusted people, add external rate limiting.
- **Not audited.** No third party has reviewed this integration. Treat it as experimental.

## Troubleshooting

- **Adapter starts but drops all messages.** Check logs for `"not in allowlist or empty"`. Confirm the allowlist entry matches exactly: phone numbers must be E.164 (leading `+`, no spaces or dashes).
- **`signal-cli --version` works but the adapter gets connection refused.** Make sure the daemon is actually running (`--http`, not just the one-shot CLI) and that the endpoint in the vault matches the daemon's bind address.
- **Messages arrive at signal-cli but never flow to wirken.** Tail the adapter logs (`wirken adapter signal`). The most common cause is an allowlist mismatch; the second most common is signal-cli returning an error response that you can spot with `curl` against the endpoint.
- **The wrong device shows as linked on your phone.** Unlink everything from your phone's Signal settings and re-run `signal-cli link` with a recognizable name.
