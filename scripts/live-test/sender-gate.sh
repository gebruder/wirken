#!/usr/bin/env bash
# Live check of the inbound sender allowlist on a running gateway, on
# Slack and Signal. Run it on the gateway host, as the user whose
# `systemctl --user` runs wirken.service, with the same WIRKEN_DATA_DIR
# (if any) the service uses.
#
#   scripts/live-test/sender-gate.sh
#
# It changes nothing beyond `wirken senders add` / `wirken senders
# remove` and one `systemctl --user restart wirken.service`. Your own
# Slack account plays the unknown sender. At the end your Signal and
# Slack ids are both admitted.
#
# Needs: wirken on PATH, systemctl and journalctl (user units),
# python3, GNU date. Everything it prints goes to a transcript file
# too; the path is printed at the end.

set -euo pipefail

TRANSCRIPT="${TMPDIR:-/tmp}/wirken-sender-gate-$(date -u +%Y%m%dT%H%M%SZ).log"
exec > >(tee -a "$TRANSCRIPT") 2>&1
trap 'echo; echo "Transcript: $TRANSCRIPT"' EXIT

# Seconds the gateway keeps one sender to one refusal row.
RATE_WINDOW=60
# How long a check waits for the gateway to have written its row.
SETTLE=30

declare -a RESULTS=()

now_utc() { date -u +%Y-%m-%dT%H:%M:%SZ; }

record() {
    # record <PASS|FAIL> <what>
    RESULTS+=("$1  $2")
    echo "  $1: $2"
}

pause() {
    echo
    echo ">>> $1"
    read -r -p ">>> Press Enter when done. " _
}

ask_yn() {
    # ask_yn <question>; prints y or n
    local answer
    while true; do
        read -r -p "$1 [y/n] " answer
        case "$answer" in
            y | Y) echo y; return ;;
            n | N) echo n; return ;;
        esac
    done
}

observe() {
    # observe <step> <question> <expected y|n>
    local got
    got=$(ask_yn "$2")
    if [ "$got" = "$3" ]; then
        record PASS "$1: you answered '$got' to: $2"
    else
        record FAIL "$1: you answered '$got', expected '$3', to: $2"
    fi
}

# Newest refusal row for <channel> <sender> at or after <since>, as
# "TIME REASON", or nothing.
refusal_since() {
    wirken senders refused "$1" -n 200 |
        awk -v id="$2" -v since="$3" '$3 == id && $1 >= since { print $1, $5; exit }'
}

# Lines "actor admitted_by" of message.inbound rows on <channel> from
# <actor> at or after <since> (RFC 3339).
inbound_since() {
    wirken audit log --action message.inbound --channel "$1" --actor "$2" \
        --since "$3" -n 50 --format json |
        python3 -I -c '
import json, sys
for e in json.load(sys.stdin)["events"]:
    print(e["actor_id"], (e.get("detail") or {}).get("admitted_by", "-"))
'
}

wait_for_refusal() {
    # wait_for_refusal <channel> <sender> <since>; prints "TIME REASON"
    local found="" i
    for ((i = 0; i < SETTLE; i++)); do
        found=$(refusal_since "$1" "$2" "$3")
        [ -n "$found" ] && break
        sleep 1
    done
    echo "$found"
}

wait_for_inbound() {
    # wait_for_inbound <channel> <sender> <since>; prints the rows
    local found="" i
    for ((i = 0; i < SETTLE; i++)); do
        found=$(inbound_since "$1" "$2" "$3")
        [ -n "$found" ] && break
        sleep 1
    done
    echo "$found"
}

countdown_until() {
    # countdown_until <epoch seconds>
    local left
    while true; do
        left=$(($1 - $(date -u +%s)))
        [ "$left" -le 0 ] && break
        printf '\r    waiting out the rate-limit window: %3ds ' "$left"
        sleep 1
    done
    printf '\r    rate-limit window passed.                 \n'
}

echo "== Step 0: version, ids, restart"
wirken --version

echo
echo "Recent message.inbound actors on signal and slack (before the restart):"
for channel in signal slack; do
    echo "  $channel:"
    wirken audit log --action message.inbound --channel "$channel" -n 20 --format json |
        python3 -I -c '
import json, sys
seen = []
for e in json.load(sys.stdin)["events"]:
    if e["actor_id"] not in seen:
        seen.append(e["actor_id"])
print("\n".join("    " + a for a in seen) or "    (none)")
'
done

echo
while true; do
    read -r -p "Your Signal sender id (as listed above): " SIGNAL_ID
    read -r -p "Your Slack user id (U...):              " SLACK_ID
    echo "  Signal: '$SIGNAL_ID'"
    echo "  Slack:  '$SLACK_ID'"
    [ "$(ask_yn "Are both correct?")" = y ] && break
done
if [ -z "$SIGNAL_ID" ] || [ -z "$SLACK_ID" ]; then
    echo "Both ids are needed." >&2
    exit 1
fi

wirken senders add signal "$SIGNAL_ID" --label live-test
RESTART_AT=$(date '+%Y-%m-%d %H:%M:%S')
systemctl --user restart wirken.service
echo "Restarted wirken.service at $RESTART_AT; waiting for the startup warnings."
WARNINGS=""
for ((i = 0; i < SETTLE; i++)); do
    WARNINGS=$(journalctl --user -u wirken.service --since "$RESTART_AT" --no-pager |
        grep -F "inbound sender allowlist" || true)
    [ -n "$WARNINGS" ] && break
    sleep 1
done
echo "${WARNINGS:-  (no sender-allowlist warning in the journal)}"
if grep -qF "allowlist for 'slack' is empty" <<<"$WARNINGS"; then
    record PASS "step 0: startup warns that slack has no entries"
else
    record FAIL "step 0: no startup warning for slack"
fi
if grep -qF "allowlist for 'signal' is empty" <<<"$WARNINGS"; then
    record FAIL "step 0: startup warns about signal, which has an entry"
else
    record PASS "step 0: no startup warning for signal"
fi
wirken senders list slack

echo
echo "== Step 1: unknown sender on Slack"
STEP1=$(now_utc)
pause "DM the bot 'ping 1' from your Slack account."
ROW1=$(wait_for_refusal slack "$SLACK_ID" "$STEP1")
if [ "$(cut -d' ' -f2 <<<"$ROW1")" = not_allowed ]; then
    record PASS "step 1: refusal row for $SLACK_ID ($ROW1)"
else
    record FAIL "step 1: no not_allowed refusal row for $SLACK_ID since $STEP1"
fi
if [ -z "$(inbound_since slack "$SLACK_ID" "$STEP1")" ]; then
    record PASS "step 1: no message.inbound row for $SLACK_ID"
else
    record FAIL "step 1: a message.inbound row exists for $SLACK_ID"
fi
observe "step 1" "Did the bot reply to 'ping 1'?" n

echo
echo "== Step 2: admitted sender on Slack"
wirken senders add slack "$SLACK_ID" --label live-test
STEP2=$(now_utc)
pause "DM the bot 'ping 2' from your Slack account."
INBOUND2=$(wait_for_inbound slack "$SLACK_ID" "$STEP2")
echo "  message.inbound rows since $STEP2: ${INBOUND2:-(none)}"
if grep -qE "^$SLACK_ID sender$" <<<"$INBOUND2"; then
    record PASS "step 2: message.inbound row with admitted_by sender"
else
    record FAIL "step 2: no message.inbound row with admitted_by sender"
fi
observe "step 2" "Did the bot reply to 'ping 2'?" y

echo
echo "== Step 3: removed sender on Slack"
if [ -n "$ROW1" ]; then
    countdown_until $(($(date -u -d "$(cut -d' ' -f1 <<<"$ROW1")" +%s) + RATE_WINDOW + 1))
else
    countdown_until $(($(date -u +%s) + RATE_WINDOW + 1))
fi
wirken senders remove slack "$SLACK_ID"
STEP3=$(now_utc)
pause "DM the bot 'ping 3' from your Slack account."
ROW3=$(wait_for_refusal slack "$SLACK_ID" "$STEP3")
if [ "$(cut -d' ' -f2 <<<"$ROW3")" = not_allowed ]; then
    record PASS "step 3: new refusal row for $SLACK_ID ($ROW3)"
else
    record FAIL "step 3: no new refusal row for $SLACK_ID since $STEP3"
fi
if [ -z "$(inbound_since slack "$SLACK_ID" "$STEP3")" ]; then
    record PASS "step 3: no message.inbound row for $SLACK_ID"
else
    record FAIL "step 3: a message.inbound row exists for $SLACK_ID"
fi
observe "step 3" "Did the bot reply to 'ping 3'?" n

echo
echo "== Step 4: re-admit Slack, check Signal, verify the chain"
wirken senders add slack "$SLACK_ID" --label live-test
pause "DM the bot one message from your Signal account."
observe "step 4" "Did the bot reply on Signal?" y
if wirken audit verify; then
    record PASS "step 4: wirken audit verify"
else
    record FAIL "step 4: wirken audit verify"
fi

echo
echo "== Summary"
FAILS=0
for line in "${RESULTS[@]}"; do
    echo "  $line"
    case "$line" in FAIL*) FAILS=$((FAILS + 1)) ;; esac
done
echo "  ${#RESULTS[@]} checks, $FAILS failed."
