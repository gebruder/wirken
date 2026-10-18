# Updating Wirken

`wirken update` checks for, installs and rolls back signed Wirken releases.
It runs only when the operator asks. Nothing checks for updates on a timer,
in the background or at gateway start.

```bash
wirken update --check                 # report; changes nothing
wirken update                         # install the latest release
wirken update --to 2.3.1              # install this release
wirken update --to 2.2.0 --allow-downgrade
wirken update --rollback              # restore the binary the last update replaced
wirken status                         # this binary's version and build; no network
```

`wirken update` is for Linux and macOS release binaries. It refuses on
Windows, and it refuses a binary built from source; see
[What it does not do](#what-it-does-not-do).

## The release manifest

Each release from 2.3.0 on publishes `releases.json` and its signature,
`releases.json.sig`, beside the binaries. The manifest is cumulative: it
lists every published release, newest first, with the date it was issued,
whether it carries security fixes, a one-line summary, and the sha256 of
each release artifact. A release is marked as a security release when its
CHANGELOG section has a `### Security` heading. The manifest as a whole
carries an `issued_at` timestamp.

The signature is an SSH signature under the namespace
`wirken-release-manifest`, made by the release key in [KEYS](../KEYS). The
binary verifies it in process against the release keys compiled into it.
There is no runtime override for those keys: not a flag, not a config file,
not an environment variable. A manifest signed by any other key is refused,
and nothing in a manifest is read before its signature verifies.
[signing.md](signing.md#release-signing) covers the key itself.

Releases before 2.3.0 publish no manifest, so `--check` against them fails
with a message saying so. The first manifest, published with 2.3.0, lists
the earlier releases too.

## wirken update --check

Fetches `releases.json` and `releases.json.sig`, verifies them, and
reports:

- the installed version and target;
- the latest release and the date it was issued;
- when the manifest was issued, where it came from, and the fingerprint of
  the key that signed it;
- whether any release newer than the installed one carries security fixes,
  with each one's version and summary;
- when the latest release publishes no binary for this target, that it
  does not.

`--check` downloads no binary and changes nothing installed. It does
record the manifest's `issued_at` (see [Freeze protection](#freeze-protection)).
It does not need a terminal and does not check for a running gateway, so it
can run from a script or a cron job the operator sets up.

## wirken update

Installs the latest release, or the one `--to` names. In order, it:

1. Refuses inside a Wirken `exec` (see [Inside an exec](#inside-an-exec)).
2. Refuses unless stdin is a terminal.
3. Refuses while a gateway answers on `gateway.sock`. With a service unit
   installed by `wirken setup --install-service`, the message names its stop
   command (`systemctl --user stop wirken.service` or
   `launchctl unload <plist>`); otherwise it says to stop the gateway.
   Every Wirken process is the one `wirken` file, and the gateway starts its
   adapters from it, so it is not replaced under a running gateway. A
   socket left by a gateway that crashed does not answer and does not
   block.
4. Fetches and verifies the manifest, as `--check` does, and applies
   freeze protection.
5. Refuses unless the running binary is a release binary: its sha256 must
   be the one the manifest lists for its own version and target. A binary
   built from source, or one changed since it was installed, is refused.
6. Chooses the release. One older than the installed version is refused
   unless `--allow-downgrade` is given. When the chosen release is the
   installed one, it says so and stops.
7. Prints the `--check` report and asks the operator to type the version
   to install. Anything else stops with nothing changed.
8. Downloads the binary for this target and refuses it unless its sha256
   is the manifest's.
9. Keeps the running binary beside it as `wirken.prev`, with a record of
   its version, sha256 and the manifest key that checked it in
   `wirken.prev.json`, then renames the new file over `wirken`. Both files
   are written in the binary's own directory, so the swap is a rename on
   one filesystem: the path holds either the old binary or the new one,
   never a partial file.
10. Records a `binary_installed` row on the `gateway-install` audit lane
    and seals it (see [Audit](#audit)).

Start the gateway again afterwards; the command prints how.

## wirken update --rollback

Restores `wirken.prev`. It passes the same exec, terminal and gateway
checks as an install, then refuses unless `wirken.prev` still has the
sha256 recorded in `wirken.prev.json`. It asks the operator to type
`rollback`, then swaps the two files: the restored binary takes the path
`wirken`, and the one it replaced becomes the new `wirken.prev`, so a
second rollback undoes the first. Rollback needs no network. It records a
`binary_installed` row with `rollback: true`.

Only one previous binary is kept. An update replaces `wirken.prev`.

## Freeze protection

A signed manifest stays validly signed forever. Without a check, someone
able to answer the fetch could serve an old, genuinely signed manifest that
predates a security release and so hide it.

Each install keeps the `issued_at` of the newest manifest it has verified,
with the signing key's fingerprint, in
`<data_dir>/update/manifest-state.json`. A manifest issued earlier than
that is refused. A newer one replaces the record. A record that cannot be
read refuses rather than starting over, so deleting or damaging the file
is not a quiet way past the check; remove it only knowing why it is
damaged.

Freeze protection holds a manifest to the newest one this install has
seen. It cannot tell this install about a release published after the
newest manifest it can fetch: a source that keeps serving the last
manifest the install saw is not detected.

## Mirrors

By default release files come from GitHub. The egress client allows only
`github.com` and `release-assets.githubusercontent.com`, the host GitHub's
release downloads redirect to. It follows no redirect on its own:
`wirken update` follows each one, checks the new host against the same
list, and refuses a redirect from https to http.

To fetch from a mirror instead, name it in `<data_dir>/update.json`:

```json
{ "mirror": "https://mirror.example.internal/wirken/" }
```

With a mirror set, the allowlist is the mirror's host alone, so nothing is
sent to GitHub. A mirror serves the same files under this layout:

```
<base>/releases.json
<base>/releases.json.sig
<base>/v<version>/wirken-<target>
```

`--base-url` picks a source for one run. It must be on a loopback address
(for a mirror on the same host) or be the mirror `update.json` names; any
other URL is refused, so a command line cannot point an update at an
arbitrary host. A base URL may be http or https, and may not carry
credentials or a query.

A mirror changes where files come from, not what is trusted. The manifest
must still verify against the compiled-in keys, freeze protection still
applies, and each binary must still match the manifest's sha256. A mirror
can withhold a release; it cannot substitute one.

## Audit

Every install and rollback appends a `binary_installed` row to the
`gateway-install` lane of the audit log and seals it with a signed chain
head straight after. The row carries `from_version`, `to_version`,
`binary_sha256`, `target`, `verifying_key` (the fingerprint of the release
key whose manifest checked the sha256) and `rollback`. It is forwarded by
default; see [audit-cli.md](audit-cli.md).

The row is written after the swap, so it records what happened rather
than what was about to. When the swap succeeds and the row cannot be
written, the command fails and says so.

What a row proves: the operator ran `wirken update` or `--rollback` at
that point in the chain, and at the time the installed bytes had that
sha256, checked against a manifest signed by that key. What it does not
prove: that the file is still those bytes. Wirken runs at the operator's
UID and so can anyone else at that UID; the file can be replaced by other
means, and that leaves no row.

A rollback row's `verifying_key` is the one recorded when the restored
binary was kept. A binary kept by a rollback was not checked against a
manifest at that moment, so rolling back a rollback records none.

Every binary also names its build on the chain: the `gateway.start` row's
detail and each session's opening chain head carry the version, commit
and whether the tree was dirty. See [audit-cli.md](audit-cli.md).

## wirken status

Prints the version, the commit the binary was built from, whether the
tree was dirty, how old that commit is, the target and the binary's
path. It reads only what was compiled in and makes no network request.

The age comes from the commit's own timestamp, not a build clock, so the
build embeds no time of its own. A build without the repository takes
it from `WIRKEN_BUILD_COMMIT_TIME` or `SOURCE_DATE_EPOCH`, in that order,
and reports it as unknown when neither is set.

## Inside an exec

`exec` sets `WIRKEN_EXEC` on every command it runs on the host, and
`wirken update` refuses when it is set. That stops a model from installing
a release through an `exec` the operator approved for something else. A
sandboxed `exec` has no `wirken` binary to run in the first place.

The marker is a guard, not the boundary. A command running at the
operator's UID can clear its own environment. What an `exec` may run at
all stays the operator's approval of each command; see
[permissions-and-identity.md](permissions-and-identity.md).

## What it does not do

- **Windows.** `wirken update` refuses there. Reinstall from the release
  page, as [windows.md](windows.md) describes.
- **Source builds.** A binary whose sha256 is not a release artifact is
  refused. Update one by rebuilding from source.
- **Provenance in the binary.** `wirken update` checks a binary's sha256
  against the signed manifest. It does not verify build provenance or
  attestations; [signing.md](signing.md#build-provenance) covers the
  provenance a release publishes and how to check it by hand.
- **Automatic checks.** Nothing runs without the operator asking.
- **Restarting the gateway.** The operator stops it before an update and
  starts it after.
