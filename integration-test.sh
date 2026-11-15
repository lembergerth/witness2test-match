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
# witness.yml, a C program, and an expected-verdict or expected-error file.
# An expected-verdict file contains the verdict string the binary's output is
# expected to contain, e.g. "NotConfirmed" or "Confirmed no-overflow". An
# expected-error file contains the error message the binary is expected to
# print when it exits with status 1.
# Optional per-case files: property.prp (passed as --property) and model
# (containing ILP32 or LP64, passed as --model).

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
  expect_error=false
  if [[ -f "$dir/expected-error" ]]; then
    expected_file="$dir/expected-error"
    expect_error=true
  fi
  if [[ ! -f "$witness" || -z "$program" || ! -f "$program" || ! -f "$expected_file" ]]; then
    echo "skip: $name (missing required file)" >&2
    continue
  fi
  expected="$(sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' "$expected_file" | tr -d '\n')"
  extra_args=()
  if [[ -f "$dir/property.prp" ]]; then
    extra_args+=(--property "$dir/property.prp")
  fi
  if [[ -f "$dir/model" ]]; then
    extra_args+=(--model "$(tr -d '[:space:]' < "$dir/model")")
  fi
  outdir="$(mktemp -d "${TMPDIR:-/tmp}/witness2test-match-it-XXXXXX")"
  output="$("$BIN" --witness "$witness" --program "$program" --output "$outdir" --time-per-run 10 "${extra_args[@]}" 2>&1)"
  rc=$?
  if $expect_error; then
    if [[ $rc -eq 1 && "$output" == "witness2test-match: $expected" ]]; then
      echo "PASS: $name (error)"
      passes=$((passes + 1))
    else
      echo "FAIL: $name (exit $rc) — expected error: $expected"
      echo "$output" | sed 's/^/  /'
      fails=$((fails + 1))
      failed_cases+=("$name")
    fi
    rm -rf "$outdir"
    continue
  fi
  if [[ $rc -ne 0 ]]; then
    echo "FAIL: $name (exit $rc)"
    echo "$output" | sed 's/^/  /'
    fails=$((fails + 1))
    failed_cases+=("$name")
    rm -rf "$outdir"
    continue
  fi
  if grep -q "^Verdict: $expected (" <<<"$output"; then
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
