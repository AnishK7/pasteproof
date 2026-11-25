#!/usr/bin/env bash
# Fails if likely secrets are present.
#   scripts/secret-scan.sh            scan staged changes (pre-commit)
#   scripts/secret-scan.sh --all      scan every tracked file (CI)
set -euo pipefail
pattern='(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{40,}|gh[ousr]_[A-Za-z0-9]{36}|glpat-[A-Za-z0-9_-]{20}|sk-ant-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{32,}|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|xox[abprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35}|gsk_[A-Za-z0-9]{40,}|hf_[A-Za-z]{30,}|npm_[A-Za-z0-9]{36}|-----BEGIN ([A-Z]+ )?PRIVATE KEY-----)'
if [[ ${1-} == --all ]]; then
  hits=$(git grep -nIE "$pattern" -- . ':!scripts/secret-scan.sh' || true)
else
  hits=$(git diff --cached -U0 --no-color -- . ':!scripts/secret-scan.sh' | grep -E '^\+' | grep -E "$pattern" || true)
fi
if [[ -n $hits ]]; then
  echo "secret-scan: possible secret found. Remove it (and rotate it if it was real):" >&2
  echo "$hits" | cut -c1-120 >&2
  exit 1
fi
echo "secret-scan: clean"
