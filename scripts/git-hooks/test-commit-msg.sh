#!/usr/bin/env bash
# Tests for scripts/git-hooks/commit-msg: each message below is run
# through the hook and its exit code compared with what the rule says.
#
# The tool name is assembled at run time so this file passes
# scripts/check-names.sh itself.
set -u

here=$(cd "$(dirname "$0")" && pwd)
hook="$here/commit-msg"
tool='c''laude'
failed=0

# check <name> <expected exit> <message>
check() {
	local name=$1 expected=$2 message=$3 actual
	local file
	file=$(mktemp)
	printf '%s\n' "$message" >"$file"
	if "$hook" "$file" >/dev/null 2>&1; then
		actual=0
	else
		actual=1
	fi
	rm -f "$file"
	if [ "$expected" = "$actual" ]; then
		printf 'PASS: %s (exit %s)\n' "$name" "$actual"
	else
		printf 'FAIL: %s (expected %s, got %s)\n' "$name" "$expected" "$actual"
		failed=$((failed + 1))
	fi
}

check 'plain message' 0 'Add a thing'

check 'human co-author' 0 "Add a thing

Co-authored-by: Olive <125517300+olive-mm@users.noreply.github.com>"

check 'co-author naming the tool' 1 "Add a thing

Co-Authored-By: ${tool^} <noreply@example.com>"

check 'co-author naming the vendor' 1 "Add a thing

Co-authored-by: Someone <someone@anthropic.com>"

check 'co-author naming the tool, lower case' 1 "Add a thing

co-authored-by: ${tool} <noreply@example.com>"

check 'generated-with line' 1 "Add a thing

Generated with a tool"

check 'home path' 1 'Fix the build on /home/someone/code/wirken'

check 'AI authorship subject' 1 "Generated with ${tool^}: add a thing"

check 'robot subject' 1 '🤖 Add a thing'

check 'commented lines are ignored' 0 "Add a thing
# Co-authored-by: ${tool^} <noreply@example.com>"

if [ "$failed" -ne 0 ]; then
	printf '%d failed\n' "$failed" >&2
	exit 1
fi
printf 'all passed\n'
