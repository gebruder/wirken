#!/usr/bin/env bash
# Install wirken's local git hooks as symlinks into .git/hooks/.
# Idempotent. Refuses to overwrite a non-symlink target.
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
src_dir="$repo_root/scripts/git-hooks"
dest_dir="$repo_root/.git/hooks"

for hook in commit-msg pre-commit; do
	src="$src_dir/$hook"
	dest="$dest_dir/$hook"
	if [ -e "$dest" ] && [ ! -L "$dest" ]; then
		printf 'install.sh: %s exists and is not a symlink; inspect before overwriting.\n' "$dest" >&2
		exit 1
	fi
	chmod +x "$src"
	ln -sf "$src" "$dest"
	printf 'installed: %s -> %s\n' "$dest" "$src"
done
