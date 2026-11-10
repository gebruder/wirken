#!/usr/bin/env bash
# The local gate: the checks CI runs on a push that a workstation can
# run, in one pass, before a commit is pushed.
#
#     scripts/gate.sh
#
# Every step runs and reports its own exit status, and the gate exits
# non-zero if any step did. A step's output is kept in a log named on
# its line. The advisory step is first because it is the one that can
# turn red with no change to the tree: an advisory published since the
# last green run fails it against the lockfile already on main.
#
# Not run here: Fuzz, Miri, MSRV and the Windows-target clippy, which
# need toolchains this script does not install. CI runs them.
set -uo pipefail

cd "$(git rev-parse --show-toplevel)" || exit 2

CI=.github/workflows/ci.yml
# The advisory, ban, licence and source check, word for word as the
# Deny job runs it.
DENY=(cargo deny --log-level warn --manifest-path ./Cargo.toml --all-features check)

logs=$(mktemp -d "${TMPDIR:-/tmp}/wirken-gate.XXXXXX")
failed=0

step() {
	local name=$1
	shift
	local log="$logs/$name.log"
	"$@" >"$log" 2>&1
	local rc=$?
	printf '%-8s exit %d  %s\n' "$name" "$rc" "$log"
	[ "$rc" -eq 0 ] || failed=1
}

# The command above is CI's or this gate checks something else. Read
# out of the workflow on every run, so the two cannot drift apart.
same_as_ci() {
	grep -qF -- "run: ${DENY[*]}" "$CI" || {
		echo "the Deny job in $CI does not run: ${DENY[*]}"
		return 1
	}
	local pinned have
	pinned=$(sed -n 's/^ *VERSION=\([0-9.]*\)$/\1/p' "$CI" | head -1)
	have=$(cargo deny --version 2>/dev/null | awk '{print $2}')
	[ -n "$have" ] || {
		echo "cargo-deny is not installed; CI pins $pinned"
		return 1
	}
	[ "$have" = "$pinned" ] || {
		echo "cargo-deny $have is installed and CI pins $pinned"
		return 1
	}
}

step deny-ci same_as_ci
step deny "${DENY[@]}"
step fmt cargo fmt --check
step clippy cargo clippy --workspace --all-targets -- -D warnings
step unsafe cargo clippy --workspace --all-targets -- -D clippy::undocumented_unsafe_blocks
step test cargo test --workspace
step lints python3 -W error::ResourceWarning scripts/source_lints.py
step names scripts/check-names.sh
step hooks scripts/git-hooks/test-commit-msg.sh
for t in scripts/test_*.py; do
	step "$(basename "$t" .py)" python3 -W error::ResourceWarning "$t"
done

if [ "$failed" -ne 0 ]; then
	echo "gate: failed"
	exit 1
fi
echo "gate: passed"
