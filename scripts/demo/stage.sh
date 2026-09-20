#!/usr/bin/env bash
#
# The hostile-model demo, as five verbs. README.md says what each one
# shows and carries the output of a full pass.
#
#   up      everything before the first prompt, silently
#   ask     the one visible run; the presenter answers the prompts
#   skills  the refusal at load
#   verify  the chain, one edit, the chain again
#   down    stop the server, remove the scratch dir
#
# `wirken` comes from PATH unless WIRKEN names another binary. Nothing
# here touches ~/.wirken: WIRKEN_DATA_DIR is set to a scratch dir under
# this folder, and every process resolves the data directory through
# it. Each verb can be run twice.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WIRKEN="${WIRKEN:-wirken}"
PORT="${PORT:-8099}"

export WIRKEN_DATA_DIR="$HERE/state"
export WIRKEN_VAULT_PASSPHRASE="demo-passphrase"

DB="$WIRKEN_DATA_DIR/audit.db"
PIDFILE="$WIRKEN_DATA_DIR/hostile_model.pid"
ANCHOR="$WIRKEN_DATA_DIR/audit/audit-signing.pub"
PROMPT='summarise the release notes'

die() {
    printf 'stage.sh: %s\n' "$1" >&2
    exit 1
}

# The pid of a hostile_model.py serving this port, by reading each
# process's argv. Not a pattern kill: `pkill -f hostile_model.py` also
# matches any shell whose own command line mentions it, this one
# included, which is how the first draft killed its caller.
model_pid() {
    python3 - "$PORT" <<'PY'
import os, sys
port = sys.argv[1]
for entry in os.listdir("/proc"):
    if not entry.isdigit():
        continue
    try:
        with open(f"/proc/{entry}/cmdline", "rb") as fh:
            argv = fh.read().split(b"\0")
    except OSError:
        continue
    argv = [a.decode("utf-8", "replace") for a in argv if a]
    if not any(a.endswith("hostile_model.py") for a in argv):
        continue
    if "--port" in argv and argv[argv.index("--port") + 1 :][:1] == [port]:
        print(entry)
        break
PY
}

# One connect attempt, for "is it already up".
listening() {
    python3 - "$PORT" <<'PY'
import socket, sys
probe = socket.socket()
probe.settimeout(0.2)
sys.exit(0 if probe.connect_ex(("127.0.0.1", int(sys.argv[1]))) == 0 else 1)
PY
}

# Connect attempts until it answers or ten seconds pass.
wait_listening() {
    python3 - "$PORT" <<'PY'
import socket, sys, time
port = int(sys.argv[1])
deadline = time.time() + 10
while time.time() < deadline:
    probe = socket.socket()
    probe.settimeout(0.2)
    if probe.connect_ex(("127.0.0.1", port)) == 0:
        sys.exit(0)
    probe.close()
    time.sleep(0.1)
sys.exit(1)
PY
}

# Where an approved `exec` would run, by the same two inputs the agent
# reads: the sandbox mode from sandbox.json (absent means the default,
# ExecOnly) and whether the Docker daemon answers on the default local
# socket. Nothing on the audit chain records this after the fact, so
# `up` says it before anyone answers a prompt.
exec_lands() {
    python3 - "$WIRKEN_DATA_DIR" <<'PY'
import json, pathlib, socket, sys

data_dir = pathlib.Path(sys.argv[1])
mode = "exec_only"
config = data_dir / "sandbox.json"
if config.is_file():
    try:
        mode = str(json.loads(config.read_text()).get("mode", mode)).lower()
    except (OSError, ValueError):
        pass

if mode == "off":
    print("on the host (sandbox mode off)")
    sys.exit(0)

reachable = False
try:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(1.0)
    sock.connect("/var/run/docker.sock")
    sock.sendall(b"GET /version HTTP/1.1\r\nHost: docker\r\n\r\n")
    reachable = b"200 OK" in sock.recv(256)
    sock.close()
except OSError:
    reachable = False

if reachable:
    print(f"in a Docker container (sandbox mode {mode})")
else:
    print(f"nowhere: sandbox mode {mode} and Docker is not reachable, so exec is refused")
PY
}

# The denial row the edit lands on, whether or not it has been edited
# already. `exec` before the edit, `echo` after it.
target_seq() {
    sqlite3 "$DB" "SELECT MIN(seq) FROM session_events
                    WHERE payload LIKE '%\"kind\":\"permission_denied\"%'
                      AND (payload LIKE '%\"tool\":\"exec\"%'
                        OR payload LIKE '%\"tool\":\"echo\"%');"
}

# `audit verify` exits 1 on a broken chain, which is an answer and not
# an error, so it runs outside `set -e`.
run_verify() {
    local rc=0
    "$WIRKEN" audit verify --require-signed --anchor "$ANCHOR" || rc=$?
    printf 'exit=%s\n' "$rc"
}

up() {
    mkdir -p "$WIRKEN_DATA_DIR/skills"

    cat > "$WIRKEN_DATA_DIR/provider.json" <<JSON
{
  "provider": "custom",
  "model": "hostile-demo-1",
  "base_url": "http://127.0.0.1:$PORT/v1"
}
JSON

    # `wirken ask` requires a credential to exist for any non-ollama
    # provider. The scripted server never reads it.
    if ! "$WIRKEN" credentials list 2>/dev/null | grep -q 'custom-api-key'; then
        printf 'not-a-real-key\n' \
            | "$WIRKEN" credentials add custom-api-key --stdin >/dev/null 2>&1
    fi

    for bundle in demo-tampered demo-selfsigned; do
        rm -rf "${WIRKEN_DATA_DIR:?}/skills/$bundle"
        cp -r "$HERE/skills/$bundle" "$WIRKEN_DATA_DIR/skills/$bundle"
    done

    "$WIRKEN" skills trust-root "$(cat "$HERE/registry-root.pub")" >/dev/null 2>&1

    local running
    running="$(model_pid)"
    if [ -z "$running" ]; then
        # Something else on the port is not ours to adopt or to kill.
        ! listening || die "port $PORT is busy and it is not hostile_model.py"
        python3 "$HERE/hostile_model.py" --port "$PORT" \
            >"$WIRKEN_DATA_DIR/hostile_model.log" 2>&1 &
        running=$!
    fi
    printf '%s\n' "$running" > "$PIDFILE"
    wait_listening || die "the hostile model did not answer on port $PORT"

    printf 'ready: scratch %s, hostile model on 127.0.0.1:%s, approved exec runs %s\n' \
        "$WIRKEN_DATA_DIR" "$PORT" "$(exec_lands)"
}

# The approval gate attaches only when stdin is a terminal, so this
# runs in the foreground with the presenter's stdin. RUST_LOG is set
# here rather than on stage: without it every LLM call also prints
# `no pricing entry for (provider, model)`, because hostile-demo-1 is
# not in the baked pricing table.
ask() {
    listening || die "no hostile model on port $PORT; run 'up' first"
    RUST_LOG=wirken=error "$WIRKEN" ask -m "$PROMPT"
}

# The loader logs its per-skill reason through tracing, which writes
# to stdout beside the table, so the filter is on stdout and not on
# stderr. NO_COLOR keeps the escape sequences out of what gets pasted.
skills() {
    NO_COLOR=1 RUST_LOG=wirken_agent::skill=debug "$WIRKEN" skills list 2>/dev/null \
        | grep 'Failed to load skill at'
}

verify() {
    [ -f "$DB" ] || die "no audit log yet; run 'ask' first"
    local seq
    seq="$(target_seq)"
    [ -n "$seq" ] || die "no exec denial on the chain; run 'ask' first"

    printf -- '── the chain as written ──\n'
    run_verify

    printf -- '\n── one UPDATE at seq %s ──\n' "$seq"
    sqlite3 "$DB" \
        "UPDATE session_events
            SET payload = replace(payload, '\"tool\":\"exec\"', '\"tool\":\"echo\"')
          WHERE seq = $seq;"
    sqlite3 "$DB" \
        "SELECT seq || '|' || substr(payload, 1, 72)
           FROM session_events WHERE seq = $seq;"

    printf -- '\n── the chain after the edit ──\n'
    run_verify
}

# Stops whatever hostile_model.py is on the port, not only the pid
# this script wrote: an `up` from another shell leaves a server whose
# pidfile a later `down` has already removed with the scratch dir.
down() {
    local running
    running="$(model_pid)"
    [ -n "$running" ] || running="$(cat "$PIDFILE" 2>/dev/null || true)"
    [ -z "$running" ] || kill "$running" 2>/dev/null || true
    [ "$WIRKEN_DATA_DIR" = "$HERE/state" ] || die "refusing to remove $WIRKEN_DATA_DIR"
    rm -rf "${WIRKEN_DATA_DIR:?}"
    printf 'stopped: hostile model down, scratch removed\n'
}

case "${1:-}" in
    up | ask | skills | verify | down) "$1" ;;
    *)
        printf 'usage: %s {up|ask|skills|verify|down}\n' "${0##*/}" >&2
        exit 2
        ;;
esac
