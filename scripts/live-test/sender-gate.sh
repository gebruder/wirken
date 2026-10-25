#!/usr/bin/env bash
# Live check of the inbound sender allowlist against a running gateway.
# See "Checking the allowlist live" in docs/channels.md.
#
#   sender-gate.sh [options] CHANNEL...
#
#   --restart CMD    Command that restarts the gateway. Without it, the
#                    script asks you to restart it.
#   --log-cmd CMD    Command that prints the gateway's recent log, used to
#                    find the startup warnings. Without it, the script asks.
#   --from STEP      Start at STEP: prepare, unknown, admitted, removed,
#                    restore. Later steps reuse the saved state.
#   --state-dir DIR  Default: ${XDG_STATE_HOME:-~/.local/state}/wirken/live-test/sender-gate.
#   --transcript F   Default: transcript.log in the state directory.
#   --wirken BIN     Default: wirken.
#
# Each channel's id is removed in prepare and put back as found in
# restore. WIRKEN_DATA_DIR is passed through.

set -euo pipefail

STEPS=(prepare unknown admitted removed restore)
RATE_WINDOW=60
SETTLE=30

usage() {
    sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

RESTART_CMD=""
LOG_CMD=""
FROM=prepare
STATE_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/wirken/live-test/sender-gate"
TRANSCRIPT=""
WIRKEN=wirken
CHANNELS=()
while [ $# -gt 0 ]; do
    case "$1" in
        --restart) RESTART_CMD="${2:?--restart needs a value}"; shift 2 ;;
        --log-cmd) LOG_CMD="${2:?--log-cmd needs a value}"; shift 2 ;;
        --from) FROM="${2:?--from needs a value}"; shift 2 ;;
        --state-dir) STATE_DIR="${2:?--state-dir needs a value}"; shift 2 ;;
        --transcript) TRANSCRIPT="${2:?--transcript needs a value}"; shift 2 ;;
        --wirken) WIRKEN="${2:?--wirken needs a value}"; shift 2 ;;
        -h | --help) usage 0 ;;
        -*) echo "Unknown option: $1" >&2; usage 2 >&2 ;;
        *) CHANNELS+=("$1"); shift ;;
    esac
done
[ ${#CHANNELS[@]} -gt 0 ] || usage 2 >&2

FROM_INDEX=-1
for i in "${!STEPS[@]}"; do
    [ "${STEPS[$i]}" = "$FROM" ] && FROM_INDEX=$i
done
if [ "$FROM_INDEX" -lt 0 ]; then
    echo "Unknown step: $FROM (one of: ${STEPS[*]})" >&2
    exit 2
fi

for channel in "${CHANNELS[@]}"; do
    "$WIRKEN" senders list "$channel" >/dev/null
done

REPO=$(cd "$(dirname "$0")/../.." && pwd -P)
case "$STATE_DIR" in /*) ;; *) STATE_DIR="$PWD/$STATE_DIR" ;; esac
TRANSCRIPT="${TRANSCRIPT:-$STATE_DIR/transcript.log}"
case "$TRANSCRIPT" in /*) ;; *) TRANSCRIPT="$PWD/$TRANSCRIPT" ;; esac
for path in "$STATE_DIR/" "$TRANSCRIPT"; do
    case "$path" in
        "$REPO"/*) echo "Keep state and transcript outside $REPO." >&2; exit 2 ;;
    esac
done
mkdir -p "$STATE_DIR" "$(dirname "$TRANSCRIPT")"
chmod 700 "$STATE_DIR"

STATE="$STATE_DIR/state"
RESULTS="$STATE_DIR/results"
if [ "$FROM" = prepare ]; then
    : >"$STATE"
    : >"$RESULTS"
fi
touch "$STATE" "$RESULTS"
chmod 600 "$STATE" "$RESULTS"

exec > >(tee -a "$TRANSCRIPT") 2>&1
trap 'echo; echo "Transcript: $TRANSCRIPT"' EXIT
echo "== $(date -u +%Y-%m-%dT%H:%M:%SZ) from $FROM: ${CHANNELS[*]}"

# State: one "key<TAB>value" line per key, last one wins.
get() {
    awk -F'\t' -v k="$1" '$1 == k { v = $2 } END { print v }' "$STATE"
}
put() {
    printf '%s\t%s\n' "$1" "$(tr -d '\t\n' <<<"$2")" >>"$STATE"
}

now_utc() { date -u +%Y-%m-%dT%H:%M:%SZ; }

record() {
    printf '%s  %s\n' "$1" "$2" >>"$RESULTS"
    echo "  $1: $2"
}

pause() {
    echo
    echo ">>> $1"
    read -r -p ">>> Press Enter when done. " _ </dev/tty
}

ask_yn() {
    local answer
    while true; do
        read -r -p "$1 [y/n] " answer </dev/tty
        case "$answer" in
            y | Y) echo y; return ;;
            n | N) echo n; return ;;
        esac
    done
}

# observe <step> <question> <expected y|n>
observe() {
    local got
    got=$(ask_yn "$2")
    if [ "$got" = "$3" ]; then
        record PASS "$1: '$got' to: $2"
    else
        record FAIL "$1: '$got', expected '$3', to: $2"
    fi
}

# Newest refusal row for <channel> <sender> at or after <since>, as
# "TIME REASON".
refusal_since() {
    "$WIRKEN" senders refused "$1" -n 200 |
        awk -v id="$2" -v since="$3" '!f && $3 == id && $1 >= since { print $1, $5; f = 1 }'
}

# "actor admitted_by" of message.inbound rows on <channel> from <actor>
# at or after <since>.
inbound_since() {
    "$WIRKEN" audit log --action message.inbound --channel "$1" --actor "$2" \
        --since "$3" -n 50 --format json |
        python3 -I -c '
import json, sys
for e in json.load(sys.stdin)["events"]:
    print(e["actor_id"], (e.get("detail") or {}).get("admitted_by", "-"))
'
}

# wait_for <function> <args...>: retries for SETTLE seconds.
wait_for() {
    local found="" i
    for ((i = 0; i < SETTLE; i++)); do
        found=$("$@")
        [ -n "$found" ] && break
        sleep 1
    done
    echo "$found"
}

epoch() {
    python3 -I -c 'import sys, datetime
t = datetime.datetime.strptime(sys.argv[1], "%Y-%m-%dT%H:%M:%SZ")
print(int(t.replace(tzinfo=datetime.timezone.utc).timestamp()))' "$1"
}

countdown_until() {
    local left
    while true; do
        left=$(($1 - $(date -u +%s)))
        [ "$left" -le 0 ] && break
        printf '\r    rate-limit window: %3ds ' "$left"
        sleep 1
    done
    printf '\r    rate-limit window passed.\n'
}

# Label of the sender entry <id> on <channel>, and whether it exists.
entry_label() {
    "$WIRKEN" senders list "$1" |
        awk -v id="$2" '!f && $2 == "sender" && $3 == id {
            l = ""; for (i = 4; i < NF - 1; i++) l = l (l ? " " : "") $i
            print "yes\t" l; f = 1 }'
}

channel_id() {
    local id
    id=$(get "id.$1")
    if [ -z "$id" ]; then
        echo "Recent message.inbound actors on $1:" >&2
        "$WIRKEN" audit log --action message.inbound --channel "$1" -n 20 --format json |
            python3 -I -c '
import json, sys
seen = []
for e in json.load(sys.stdin)["events"]:
    if e["actor_id"] not in seen:
        seen.append(e["actor_id"])
print("\n".join("  " + a for a in seen) or "  (none)")
' >&2
        while [ -z "$id" ] || [ "$(ask_yn "Your $1 sender id is '$id'?")" != y ]; do
            read -r -p "Your sender id on $1: " id </dev/tty
        done
        put "id.$1" "$id"
    fi
    echo "$id"
}

step_prepare() {
    local channel id found before after
    "$WIRKEN" --version
    for channel in "${CHANNELS[@]}"; do
        id=$(channel_id "$channel")
        found=$(entry_label "$channel" "$id")
        put "had.$channel" "${found:+yes}"
        put "label.$channel" "$(cut -s -f2 <<<"$found")"
        "$WIRKEN" senders remove "$channel" "$id"
    done

    before="$STATE_DIR/log.before"
    after="$STATE_DIR/log.after"
    : >"$before"
    if [ -n "$LOG_CMD" ]; then
        bash -c "$LOG_CMD" >"$before" 2>&1 || true
    fi
    if [ -n "$RESTART_CMD" ]; then
        bash -c "$RESTART_CMD"
    else
        pause "Restart the gateway."
    fi
    for channel in "${CHANNELS[@]}"; do
        if grep -q '^No senders admitted' <<<"$("$WIRKEN" senders list "$channel")"; then
            put "empty.$channel" y
        else
            put "empty.$channel" n
        fi
    done
    if [ -z "$LOG_CMD" ]; then
        for channel in "${CHANNELS[@]}"; do
            observe prepare \
                "Did the gateway log that the allowlist for '$channel' is empty?" \
                "$(get "empty.$channel")"
        done
        return
    fi
    # Wait for every expected warning, or SETTLE seconds.
    local missing warned i
    for ((i = 0; i < SETTLE; i++)); do
        bash -c "$LOG_CMD" 2>&1 | grep -vxFf "$before" >"$after" || true
        missing=n
        for channel in "${CHANNELS[@]}"; do
            if [ "$(get "empty.$channel")" = y ] &&
                ! grep -qF "allowlist for '$channel' is empty" "$after"; then
                missing=y
            fi
        done
        [ "$missing" = n ] && [ "$i" -ge 5 ] && break
        sleep 1
    done
    for channel in "${CHANNELS[@]}"; do
        warned=n
        grep -qF "allowlist for '$channel' is empty" "$after" && warned=y
        if [ "$warned" = "$(get "empty.$channel")" ]; then
            record PASS "prepare: $channel empty=$(get "empty.$channel"), startup warning=$warned"
        else
            record FAIL "prepare: $channel empty=$(get "empty.$channel"), startup warning=$warned"
        fi
    done
    rm -f "$before" "$after"
}

step_unknown() {
    local channel id since row
    for channel in "${CHANNELS[@]}"; do
        id=$(channel_id "$channel")
        since=$(now_utc)
        pause "Message the bot 'ping unknown' on $channel."
        row=$(wait_for refusal_since "$channel" "$id" "$since")
        if [ "$(cut -d' ' -f2 <<<"$row")" = not_allowed ]; then
            record PASS "unknown: $channel refusal row for $id ($row)"
        else
            record FAIL "unknown: $channel no not_allowed row for $id since $since"
        fi
        if [ -z "$(inbound_since "$channel" "$id" "$since")" ]; then
            record PASS "unknown: $channel no message.inbound row"
        else
            record FAIL "unknown: $channel message.inbound row present"
        fi
        observe unknown "Did the bot reply on $channel?" n
    done
}

step_admitted() {
    local channel id since rows
    for channel in "${CHANNELS[@]}"; do
        id=$(channel_id "$channel")
        "$WIRKEN" senders add "$channel" "$id" --label live-test
        since=$(now_utc)
        pause "Message the bot 'ping admitted' on $channel."
        rows=$(wait_for inbound_since "$channel" "$id" "$since")
        echo "  message.inbound rows: ${rows:-(none)}"
        if grep -qxF "$id sender" <<<"$rows"; then
            record PASS "admitted: $channel message.inbound row, admitted_by sender"
        else
            record FAIL "admitted: $channel no message.inbound row with admitted_by sender"
        fi
        observe admitted "Did the bot reply on $channel?" y
    done
}

step_removed() {
    local channel id since row last
    for channel in "${CHANNELS[@]}"; do
        id=$(channel_id "$channel")
        last=$(refusal_since "$channel" "$id" 0 | cut -d' ' -f1)
        if [ -n "$last" ]; then
            countdown_until $(($(epoch "$last") + RATE_WINDOW + 1))
        fi
        "$WIRKEN" senders remove "$channel" "$id"
        since=$(now_utc)
        pause "Message the bot 'ping removed' on $channel."
        row=$(wait_for refusal_since "$channel" "$id" "$since")
        if [ "$(cut -d' ' -f2 <<<"$row")" = not_allowed ]; then
            record PASS "removed: $channel refusal row for $id ($row)"
        else
            record FAIL "removed: $channel no not_allowed row for $id since $since"
        fi
        if [ -z "$(inbound_since "$channel" "$id" "$since")" ]; then
            record PASS "removed: $channel no message.inbound row"
        else
            record FAIL "removed: $channel message.inbound row present"
        fi
        observe removed "Did the bot reply on $channel?" n
    done
}

step_restore() {
    local channel id label
    for channel in "${CHANNELS[@]}"; do
        id=$(channel_id "$channel")
        if [ "$(get "had.$channel")" = yes ]; then
            label=$(get "label.$channel")
            "$WIRKEN" senders add "$channel" "$id" ${label:+--label "$label"}
        else
            "$WIRKEN" senders remove "$channel" "$id"
        fi
    done
    "$WIRKEN" senders list
    if "$WIRKEN" audit verify; then
        record PASS "restore: wirken audit verify"
    else
        record FAIL "restore: wirken audit verify"
    fi
}

for ((s = FROM_INDEX; s < ${#STEPS[@]}; s++)); do
    echo
    echo "== Step ${STEPS[$s]}"
    "step_${STEPS[$s]}"
done

echo
echo "== Summary"
cat "$RESULTS"
echo "  $(wc -l <"$RESULTS") checks, $(grep -c '^FAIL' "$RESULTS" || true) failed."
