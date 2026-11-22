#!/bin/sh
# Point this repo's git hooks at scripts/git-hooks (pre-commit secret scan).
set -eu
root=$(git rev-parse --show-toplevel)
chmod +x "$root/scripts/git-hooks/pre-commit"
git -C "$root" config core.hooksPath scripts/git-hooks
echo "hooks installed: core.hooksPath=scripts/git-hooks (pre-commit runs gitleaks)"
