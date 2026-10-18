#!/usr/bin/env bash
# Fail on the AI-tool name in a tracked file or path, and on an
# attribution line in a commit message.
#
#   scripts/check-names.sh [<rev-range>]
#
# Files: every tracked path and every tracked file's contents, case
# insensitive. A file may carry the name only when
# scripts/check-names.allow lists its exact path with a reason. That
# list is for functional model identifiers in code and tests; a
# documentation path in it fails, and so does an entry for a file that
# no longer carries the name.
#
# Commits: every commit in <rev-range> fails if its message has a
# co-author trailer naming the tool or its vendor, or a line starting
# "generated with". The default range runs from the last tag before
# HEAD.
#
# The name is written as a character class so this script passes its
# own check.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

name='c[l]aude'
allow_file=scripts/check-names.allow

fail=0
problem() {
	printf 'check-names: %s\n' "$1" >&2
	fail=1
}

# The allowlist: exact path, whitespace, reason.
declare -A allowed=()
if [ -f "$allow_file" ]; then
	while IFS= read -r line || [ -n "$line" ]; do
		[[ $line =~ ^[[:space:]]*(#|$) ]] && continue
		path=${line%%[[:space:]]*}
		reason=${line#"$path"}
		reason=${reason#"${reason%%[![:space:]]*}"}
		if [ -z "$reason" ]; then
			problem "$allow_file: $path has no reason"
			continue
		fi
		case $path in
		docs/* | *.md | *.MD)
			problem "$allow_file: $path is documentation, which is never allowlisted"
			continue
			;;
		esac
		if ! git ls-files --error-unmatch -- "$path" >/dev/null 2>&1; then
			problem "$allow_file: $path is not a tracked file"
			continue
		fi
		allowed[$path]=1
	done <"$allow_file"
fi

# Paths.
files=0
shopt -s nocasematch
while IFS= read -r -d '' path; do
	files=$((files + 1))
	if [[ $path =~ $name ]]; then
		problem "a tracked path carries the name: $path"
	fi
done < <(git ls-files -z)
shopt -u nocasematch

# Contents.
declare -A hit=()
while IFS= read -r -d '' path; do
	hit[$path]=1
done < <(git grep -z -l -i -E -e "$name" || true)

mapfile -t hits < <(printf '%s\n' "${!hit[@]}" | LC_ALL=C sort)
for path in "${hits[@]}"; do
	[ -z "$path" ] && continue
	[ -n "${allowed[$path]:-}" ] && continue
	problem "$path carries the name:"
	if ! git grep -n -i -I -E -e "$name" -- "$path" | sed 's/^/    /' >&2; then
		printf '    (binary file)\n' >&2
	fi
done
for path in "${!allowed[@]}"; do
	if [ -z "${hit[$path]:-}" ]; then
		problem "$allow_file: $path no longer carries the name; remove its entry"
	fi
done

# Commits.
if [ $# -gt 0 ]; then
	log_args=("$1")
	range=$1
elif base=$(git describe --tags --abbrev=0 HEAD^ 2>/dev/null); then
	log_args=("$base..HEAD")
	range="$base..HEAD"
else
	log_args=(-1 HEAD)
	range=HEAD
fi
coauthor="^[[:space:]]*co-authored-by:.*($name|anthropic)"
generated='^[^[:alnum:]]*generated with'
commits=0
shopt -s nocasematch
while IFS= read -r -d $'\x1e' record; do
	record=${record#$'\n'}
	[ -z "$record" ] && continue
	sha=${record%%$'\n'*}
	body=${record#*$'\n'}
	commits=$((commits + 1))
	while IFS= read -r l; do
		if [[ $l =~ $coauthor || $l =~ $generated ]]; then
			problem "commit ${sha:0:12} carries an attribution line: $l"
		fi
	done <<<"$body"
done < <(git log --format='%H%n%B%x1e' "${log_args[@]}")
shopt -u nocasematch

if [ $fail -ne 0 ]; then
	exit 1
fi
printf 'check-names: %d tracked files clean (%d allowlisted), %d commits in %s clean\n' \
	"$files" "${#allowed[@]}" "$commits" "$range"
