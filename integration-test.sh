#!/usr/bin/env bash
# This file is part of witness2test-match,
# a tool to turn SV-COMP violation witnesses (format v2) into executable tests.
# https://github.com/lembergerth/witness2test-match
#
# SPDX-FileCopyrightText: 2026 Thomas Lemberger <https://thomaslemberger.com>
#
# SPDX-License-Identifier: Apache-2.0
#
# Runs witness2test-match against every subdirectory of integration/ that has a
# witness.yml, program.c, and expected-verdict file. Each expected-verdict
# file contains the verdict string the binary's output is expected to contain.

set -u

cd "$(dirname "$0")"

BIN=bin/witness2test-match
if [[ ! -x "$BIN" ]]; then
  echo "binary $BIN not built; run 'make build' first" >&2
  exit 2
fi

passes=0
fails=0
failed_cases=()

for dir in integration/*/; do
  name="$(basename "$dir")"
  witness="$dir/witness.yml"
  program="$(find "$dir" -maxdepth 1 -name '*.c' -print -quit)"
  expected_file="$dir/expected-verdict"
  if [[ ! -f "$witness" || -z "$program" || ! -f "$program" || ! -f "$expected_file" ]]; then
    echo "skip: $name (missing required file)" >&2
    continue
  fi
  expected="$(tr -d '[:space:]' < "$expected_file")"
  outdir="$(mktemp -d "${TMPDIR:-/tmp}/witness2test-match-it-XXXXXX")"
  output="$("$BIN" --witness "$witness" --program "$program" --output "$outdir" --time-per-run 10 2>&1)"
  rc=$?
  if [[ $rc -ne 0 ]]; then
    echo "FAIL: $name (exit $rc)"
    echo "$output" | sed 's/^/  /'
    fails=$((fails + 1))
    failed_cases+=("$name")
    rm -rf "$outdir"
    continue
  fi
  if grep -q "Verdict: $expected" <<<"$output"; then
    echo "PASS: $name ($expected)"
    passes=$((passes + 1))
  else
    echo "FAIL: $name — expected verdict $expected"
    echo "$output" | sed 's/^/  /'
    fails=$((fails + 1))
    failed_cases+=("$name")
  fi
  rm -rf "$outdir"
done

echo
echo "Summary: $passes passed, $fails failed"
if [[ $fails -gt 0 ]]; then
  echo "Failed cases: ${failed_cases[*]}"
  exit 1
fi
