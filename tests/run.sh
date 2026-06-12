#!/usr/bin/env bash
# Shared test entrypoint for jira-issue-from-sarif. CI (.github/workflows/test.yml)
# invokes this exact script, so a local run and a CI run can never check different
# things or drift apart.
#
# Runs, against the standard library only (no jira package, no network):
#   1. py_compile  - syntax check on every tracked *.py
#   2. unittest    - the FakeJira-backed suite (dedup, severity, 429, dry-run,
#                    fingerprint contract, JQL safety, failure isolation)
#
# Usage: tests/run.sh   (override the interpreter with PYTHON=python3.11 tests/run.sh)
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

PY="${PYTHON:-python3}"

# Enumerate tracked Python sources via git so untracked / vendored files are never
# checked. A read loop (not mapfile) keeps this working on bash 3.2 (macOS default).
sources=()
while IFS= read -r src; do
    sources+=("$src")
done < <(git ls-files '*.py')

if [ "${#sources[@]}" -eq 0 ]; then
    echo "No tracked *.py files found; nothing to check."
    exit 0
fi

echo "Syntax-checking ${#sources[@]} Python file(s) with $PY..."
"$PY" -m py_compile "${sources[@]}"

echo "Running unit tests..."
"$PY" -m unittest test_sarif_to_jira -v

echo "OK: py_compile and unit tests passed."
