#!/bin/bash
# deploy.sh — use this instead of "git push" to deploy the TryFreed app.
# Updates version.txt automatically so the live app detects the new version
# and reloads for all users within ~3 minutes.

set -e

# Update version (Unix timestamp)
echo $(date +%s) > login/version.txt

# Stage and commit (or amend if only version.txt changed)
git add login/version.txt

if git diff --cached --quiet; then
  echo "Nothing to commit."
else
  git commit -m "chore: bump version for deploy"
fi

git push origin main

echo ""
echo "✓ Deploy feito. O app vai detectar a nova versão automaticamente."
