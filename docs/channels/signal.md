# Signal

```bash
wirken channel add signal
```

Signal is different from every other wirken channel. There is no bot API: you connect by running [signal-cli](https://github.com/AsamK/signal-cli) as a local JSON-RPC daemon and pointing wirken at it. That daemon acts as a real Signal client, under your identity. This page documents how to set it up **and** the exposure that comes with it, so you can decide whether to run it and how to harden it.

> **0.8.0 transport change.** The adapter previously polled signal-cli's HTTP JSON-RPC endpoint with a `receive` call per tick. signal-cli 0.14.x's HTTP daemon auto-consumes inbound messages in the background and rejects concurrent `receive` RPCs, which broke the polling loop. The adapter now speaks newline-delimited JSON-RPC over a Unix socket and consumes `subscribeReceive` notifications the daemon pushes unprompted. Pre-0.8.0 installs that stored an HTTP URL as `signal-endpoint` must re-enter the endpoint via `wirken setup` or `wirken channel add signal`; the adapter rejects HTTP URLs at startup with a migration error.

## What you get

- Inbound: wirken subscribes to signal-cli's JSON-RPC push stream and forwards incoming Signal messages (DMs and groups) to the gateway as normal channel messages. No polling.
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

### 3. Run the daemon bound to a Unix socket

The daemon's JSON-RPC transport has no authentication: any process that can open the socket can send Signal messages as you. A filesystem-permissioned Unix socket is the default because it reduces the reachable surface to processes on the same host running as the same uid (or members of a group you grant via `chmod`).

```bash
signal-cli -a +15551234567 daemon --socket /tmp/signal-cli.sock
```

Leave that running in a terminal or under a supervisor (systemd user unit, tmux, etc.). Verify the socket exists and speaks JSON-RPC:

```bash
ls -l /tmp/signal-cli.sock   # must be a socket file owned by you (srw-------)
echo '{"jsonrpc":"2.0","method":"version","id":1}' | socat - UNIX-CONNECT:/tmp/signal-cli.sock
```

The response should be a single JSON line containing the signal-cli version. If you need a different path (e.g., a XDG-respecting location), pass it to `--socket` and provide the same path to wirken below.

If you used `--http` with a prior wirken release, remove that invocation — the adapter no longer speaks HTTP.

### 4. Register with wirken

```bash
wirken channel add signal
```

You'll be prompted for:

- **Registered phone number**: the E.164 number you linked or registered.
- **signal-cli socket path**: defaults to `/tmp/signal-cli.sock`. Accepts a bare path or `unix:///absolute/path`. HTTP URLs are rejected.
- **Allowed senders (comma-separated)**: **required**. See the next section.

### 5. Configure the sender allowlist

The Signal adapter is fail-closed: an empty allowlist drops every inbound message. The allowlist IS the authorization — anyone whose E.164 number or group ID is in it can drive the agent; anyone not in it has their messages dropped before the LLM ever sees them. There is no additional per-sender challenge.

Setup prompts you for the initial list. To edit it afterward, rotate the vault entry. There is no one-shot "set" command; remove and re-add to change the full list:

```bash
wirken credentials remove signal-allowed-senders
wirken credentials add signal-allowed-senders --channel signal
# prompts for the new comma-separated value
```

Or pipe the value for scripted updates:

```bash
echo "+15551234567,+15559876543,group-abc-xyz=" \
  | wirken credentials add signal-allowed-senders --channel signal --stdin
```

Entries are matched against the inbound message's conversation:

- **1:1 DMs**: the sender's E.164 phone number must be in the list.
- **Group messages**: the Signal group ID must be in the list. The sender inside the group is not checked; group membership is your access control.

To find a group's ID:

```bash
signal-cli -a +15551234567 listGroups
```

If you change the allowlist, restart `wirken run` so the adapter re-reads the vault.

## Signal-specific exposure

The project-wide agent controls (permission tiers, workspace path confinement, injection detection, sandboxing, audit trail) are described in [`docs/security-properties.md`](../security-properties.md). Read that first. This section only covers what is different or additional for the Signal adapter.

### The allowlist is the only thing between Signal contacts and the LLM

There is no per-sender auth in Signal; anyone who has your linked number can send you a message. The allowlist is therefore the entire perimeter, and the adapter fails closed on an empty list. Everything past the allowlist is inside the trust boundary: the LLM sees the message, the tool registry is in scope, and the same permission tiers that apply to every other channel apply here. If you add someone to the allowlist, you are trusting them with whatever Tier 1 actions the agent can perform unprompted, plus any Tier 2 approvals you have previously granted (see next point).

### Pre-existing Tier 2 approvals apply to Signal messages too

A Tier 2 approval is recorded per-agent, not per-channel. If you have already approved `exec` of, say, `bash` for the default agent (perhaps through an earlier Telegram or CLI session), then a message from an allowlisted Signal sender that triggers `exec bash ...` will run without prompting. Before putting the Signal adapter in front of an agent, review `wirken permission list <agent_id>` and revoke grants you are not comfortable exposing to Signal traffic.

### Prompt-injection detection is monitoring, not prevention

The gateway's `InjectionDetector` (see `docs/security-properties.md` → MEASURE 2.6) scans every inbound Signal message for role-switching, instruction overrides, base64-encoded shell, tool-call injection, and system-prompt extraction. When it fires, it annotates the `message.inbound` audit event and emits a separate `message.threat_flagged` event for SIEM. It does **not** block the message, rewrite it, add a warning to the LLM turn, or gate tool execution on the threat level. Tracking higher-confidence responses to Critical-severity flags is an open backlog item.

### signal-cli daemon socket has no authentication

The signal-cli JSON-RPC socket is not authenticated. Any local process that can open the socket can send Signal messages as you. Mitigations (by default, filesystem permissions on the socket do most of the work):

- Use a socket path inside a directory you own (`$XDG_RUNTIME_DIR`, `~/.local/share/signal-cli/`, etc.). `/tmp` is fine on a single-user host; on shared hosts, prefer a directory outside `/tmp` that is `chmod 700`.
- Run signal-cli as a dedicated user on multi-user hosts and only grant that uid's group access to the socket.
- DBus transport is also available; the wirken adapter speaks JSON-RPC over a Unix socket.

### signal-cli credential storage

Linking produces an account state directory at `~/.local/share/signal-cli/data/` containing your Signal protocol keys in cleartext. Whoever holds that directory can impersonate you on Signal indefinitely, until you manually unlink the device from your phone.

- Back it up only to an encrypted location. File-sync tools (Dropbox, Google Drive, rsync) that pick up `~/.local/share/signal-cli/` effectively hand over your Signal identity.
- If you suspect compromise, open Signal on your phone → Settings → Linked devices → remove the wirken device. That rotates the relevant keys.
- `chmod 700 ~/.local/share/signal-cli/` is a reasonable baseline.

### What Signal's crypto does and doesn't buy you

Signal's end-to-end encryption is not what fails here. An allowlisted message arrives authenticated and decrypted; its text is placed into an LLM prompt; the LLM may act on attacker-controlled instructions. The transport is cryptographically sound; the application layer above it is a classic prompt-injection surface. The allowlist, the permission tiers, and the injection detector's audit trail are what bound the blast radius.

## Operational constraints

### Messages delivered during a signal-cli restart are not replayed to wirken

`signal-cli --socket` streams envelopes to currently-subscribed JSON-RPC listeners only. When signal-cli restarts (crash, manual kill, systemd restart), any Signal message that reaches the daemon before wirken's adapter has reconnected and resubscribed is written to the daemon's stdout log and is **not** delivered to the adapter's subscription. The hash chain across the disconnect is intact — the missed message simply never enters the session log — but the agent will not answer it.

Practical implications:

- Keep signal-cli running under a supervisor (systemd user unit, tmux + auto-respawn, or similar) so restart windows stay short.
- If an inbound DM arrives during a restart window and needs an agent response, the sender has to send it again.
- Observability: the daemon's stdout shows `Envelope from: ...` for the lost DM. Cross-reference with wirken's log to distinguish "adapter never saw it" from "adapter dropped it" (the latter would log `not in allowlist or empty`).

This is a signal-cli architecture property, not a wirken bug. Tracked separately if signal-cli ever adds a replay/queue RPC that wirken could call after reconnect.

## Known limitations

- **Inbound latency is pure IPC + LLM time.** 0.8.0 moved to push-based JSON-RPC over a Unix socket; no polling floor. Response latency is dominated by LLM turn time.
- **No typing indicators, reactions, or read receipts.** We drop everything except text messages.
- **Own-send echoes are suppressed, not forwarded.** Signal mirrors every send to every linked device including the daemon; the adapter filters those by message timestamp so the agent does not re-process its own replies. Sends from other linked devices (your phone messaging a contact) are dropped by default — set `WIRKEN_SIGNAL_FORWARD_LINKED_DEVICE_SENDS=1` if you want those routed in too, e.g., for test-to-self smoke checks.
- **Approval is coarse.** Tier 2 shell approvals are keyed on the first token of the command. Finer-grained patterns are not yet supported.
- **No rate limiting on the adapter.** An allowlisted sender spamming messages will spam the LLM and your API bill. If you expose this to more than a handful of trusted people, add external rate limiting.
- **Not audited.** No third party has reviewed this integration. Treat it as experimental.

## Troubleshooting

- **Adapter starts but drops all messages.** Check logs for `"not in allowlist or empty"`. Confirm the allowlist entry matches exactly: phone numbers must be E.164 (leading `+`, no spaces or dashes).
- **`signal-cli --version` works but the adapter gets connection refused.** Make sure the daemon is running with `--socket /path/to/sock` (not `--http`, which the adapter no longer speaks) and that the socket path in the vault matches.
- **Adapter logs `signal endpoint is an HTTP URL`.** Left over from a pre-0.8.0 install. Remove and re-add the endpoint:
  ```bash
  wirken credentials remove signal-endpoint
  wirken credentials add signal-endpoint --channel signal
  # enter the socket path, e.g. /tmp/signal-cli.sock
  ```
- **Adapter keeps reconnecting.** Signal-cli daemon may have crashed or been restarted; the adapter retries with exponential backoff up to 30s between attempts. Tail signal-cli's output and confirm the socket exists and responds to `version`:
  ```bash
  ls -l /tmp/signal-cli.sock
  echo '{"jsonrpc":"2.0","method":"version","id":1}' | socat - UNIX-CONNECT:/tmp/signal-cli.sock
  ```
- **Messages arrive at signal-cli but never flow to wirken.** Tail `wirken run` logs. The most common cause is an allowlist mismatch; the second most common is a sync-send being dropped because `WIRKEN_SIGNAL_FORWARD_LINKED_DEVICE_SENDS` is unset (expected for production, not for test-to-self).
- **The wrong device shows as linked on your phone.** Unlink everything from your phone's Signal settings and re-run `signal-cli link` with a recognizable name. Wait for the link command to exit on its own — killing it before the handshake completes leaves a half-initialized account directory and causes NPEs on first receive.
