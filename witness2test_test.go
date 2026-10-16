// This file is part of witness2test-match,
// a tool to turn SV-COMP violation witnesses (format v2) into executable tests.
// https://github.com/lembergerth/witness2test-match
//
// SPDX-FileCopyrightText: 2026 Thomas Lemberger <https://thomaslemberger.com>
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"witness2test/execution"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

const programWithSingleNondet = `void reach_error(){}
extern int __VERIFIER_nondet_int(void);
int main() {
  int x = __VERIFIER_nondet_int();
  if (x == 42) {
    reach_error();
    return 1;
  }
  return 0;
}
`

const witnessHitsViolation = `- entry_type: "violation_sequence"
  metadata:
    format_version: "2.0"
    uuid: "00000000-0000-0000-0000-000000000010"
    creation_time: "2026-01-01T00:00:00Z"
    producer: { name: "test", version: "0" }
    task:
      input_files: [ "program.c" ]
      input_file_hashes: { "program.c": "deadbeef" }
      specification: "G ! call(reach_error())"
      data_model: "ILP32"
      language: "C"
  content:
  - segment:
    - waypoint:
        type: "function_return"
        action: "follow"
        constraint: { value: "\\result == 42", format: "acsl_expression" }
        location: { file_name: "program.c", line: 4, column: 33 }
  - segment:
    - waypoint:
        type: "target"
        action: "follow"
        location: { file_name: "program.c", line: 6, column: 5 }
`

const witnessMissesViolation = `- entry_type: "violation_sequence"
  metadata:
    format_version: "2.0"
    uuid: "00000000-0000-0000-0000-000000000011"
    creation_time: "2026-01-01T00:00:00Z"
    producer: { name: "test", version: "0" }
    task:
      input_files: [ "program.c" ]
      input_file_hashes: { "program.c": "deadbeef" }
      specification: "G ! call(reach_error())"
      data_model: "ILP32"
      language: "C"
  content:
  - segment:
    - waypoint:
        type: "function_return"
        action: "follow"
        constraint: { value: "\\result == 0", format: "acsl_expression" }
        location: { file_name: "program.c", line: 4, column: 33 }
`

const programWithLoopNondet = `void reach_error(){}
extern int __VERIFIER_nondet_int(void);
int main() {
  int sum = 0;
  for (int i = 0; i < 3; i++) {
    sum += __VERIFIER_nondet_int();
  }
  if (sum == 99) reach_error();
  return 0;
}
`

const witnessOverflow = `- entry_type: "violation_sequence"
  metadata:
    format_version: "2.0"
    uuid: "00000000-0000-0000-0000-000000000012"
    creation_time: "2026-01-01T00:00:00Z"
    producer: { name: "test", version: "0" }
    task:
      input_files: [ "program.c" ]
      input_file_hashes: { "program.c": "deadbeef" }
      specification: "G ! call(reach_error())"
      data_model: "ILP32"
      language: "C"
  content:
  - segment:
    - waypoint:
        type: "function_return"
        action: "follow"
        constraint: { value: "\\result == 1", format: "acsl_expression" }
        location: { file_name: "program.c", line: 6, column: 34 }
`

const witnessAssumptionOnly = `- entry_type: "violation_sequence"
  metadata:
    format_version: "2.0"
    uuid: "00000000-0000-0000-0000-000000000013"
    creation_time: "2026-01-01T00:00:00Z"
    producer: { name: "test", version: "0" }
    task:
      input_files: [ "program.c" ]
      input_file_hashes: { "program.c": "deadbeef" }
      specification: "G ! call(reach_error())"
      data_model: "ILP32"
      language: "C"
  content:
  - segment:
    - waypoint:
        type: "assumption"
        action: "follow"
        constraint: { value: "x == 42", format: "c_expression" }
        location: { file_name: "program.c", line: 5, column: 3 }
`

func runPipeline(t *testing.T, programSrc, witnessSrc string) (execution.Verdict, string) {
	t.Helper()
	dir := t.TempDir()
	prog := filepath.Join(dir, "program.c")
	wit := filepath.Join(dir, "witness.yml")
	out := filepath.Join(dir, "out")
	writeFile(t, prog, programSrc)
	writeFile(t, wit, witnessSrc)
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatalf("mkdir output: %v", err)
	}
	v, instPath, err := turnWitnessToTest(wit, prog, dir, out, 5*time.Second)
	if err != nil {
		t.Fatalf("turnWitnessToTest: %v", err)
	}
	if _, statErr := os.Stat(instPath); statErr != nil {
		t.Errorf("instrumented_program.c not written at %s: %v", instPath, statErr)
	}
	return v, instPath
}

func TestTurnWitnessToTestConfirmed(t *testing.T) {
	v, _ := runPipeline(t, programWithSingleNondet, witnessHitsViolation)
	if v.Status != execution.Confirmed {
		t.Errorf("got %+v, want Confirmed", v)
	}
}

func TestTurnWitnessToTestNotConfirmed(t *testing.T) {
	v, _ := runPipeline(t, programWithSingleNondet, witnessMissesViolation)
	if v.Status != execution.NotConfirmed {
		t.Errorf("got %+v, want NotConfirmed", v)
	}
}

func TestTurnWitnessToTestInconsistent(t *testing.T) {
	v, _ := runPipeline(t, programWithLoopNondet, witnessOverflow)
	if v.Status != execution.Inconsistent {
		t.Errorf("got %+v, want WitnessInconsistent", v)
	}
}

func TestTurnWitnessToTestUnsupported(t *testing.T) {
	v, instPath := runPipeline(t, programWithSingleNondet, witnessAssumptionOnly)
	if v.Status != execution.WitnessUnsupported {
		t.Errorf("got %+v, want WitnessUnsupported", v)
	}
	if !strings.Contains(v.Stderr, "assumption=1") {
		t.Errorf("verdict diagnostic should summarize waypoints, got %q", v.Stderr)
	}
	// File must still be written for an unsupported witness.
	got, err := os.ReadFile(instPath)
	if err != nil {
		t.Fatalf("read instrumented: %v", err)
	}
	if string(got) != programWithSingleNondet {
		t.Error("for unsupported witness, instrumented_program.c should be the unchanged source")
	}
}

func TestFormatVerdictIncludesPath(t *testing.T) {
	v := execution.Verdict{Status: execution.Confirmed, ExitCode: 213}
	got := formatVerdict(v, "/tmp/out/instrumented_program.c")
	if !strings.Contains(got, "Confirmed") || !strings.Contains(got, "/tmp/out/instrumented_program.c") {
		t.Errorf("verdict line: %q", got)
	}
}

func TestFormatVerdictIncludesStderr(t *testing.T) {
	v := execution.Verdict{Status: execution.WitnessUnsupported, Stderr: "diagnostic line"}
	got := formatVerdict(v, "/tmp/x.c")
	if !strings.Contains(got, "diagnostic line") {
		t.Errorf("verdict should include stderr: %q", got)
	}
}

func TestRunMissingFlags(t *testing.T) {
	exit, msg := run(nil, os.Stdout, os.Stderr)
	if exit != 2 {
		t.Errorf("exit=%d, want 2", exit)
	}
	if !strings.Contains(msg, "required") {
		t.Errorf("error message should mention required flags: %q", msg)
	}
}

func TestRunVersion(t *testing.T) {
	exit, msg := run([]string{"--version"}, os.Stdout, os.Stderr)
	if exit != 0 || msg != "" {
		t.Errorf("got exit=%d msg=%q", exit, msg)
	}
}

func TestMainWithArgsPrintsMessageAndExits(t *testing.T) {
	if got := mainWithArgs(nil); got != 2 {
		t.Errorf("mainWithArgs(nil) = %d, want 2", got)
	}
}

func TestRunUnknownFlag(t *testing.T) {
	exit, _ := run([]string{"--no-such-flag"}, os.Stdout, os.Stderr)
	if exit != 2 {
		t.Errorf("exit=%d, want 2 for unknown flag", exit)
	}
}

func TestRunRejectsUncreatableOutputDir(t *testing.T) {
	// Output dir whose parent is a regular file → MkdirAll fails.
	dir := t.TempDir()
	blocker := filepath.Join(dir, "file")
	writeFile(t, blocker, "x")
	output := filepath.Join(blocker, "subdir")
	prog := filepath.Join(dir, "p.c")
	wit := filepath.Join(dir, "w.yml")
	writeFile(t, prog, programWithSingleNondet)
	writeFile(t, wit, witnessHitsViolation)
	exit, msg := run([]string{"--witness", wit, "--program", prog, "--output", output}, os.Stdout, os.Stderr)
	if exit != 1 || !strings.Contains(msg, "output dir") {
		t.Errorf("exit=%d msg=%q", exit, msg)
	}
}

func TestTurnWitnessToTestFailsWritingInstrumented(t *testing.T) {
	// outputDir set to a regular file → WriteFile fails.
	dir := t.TempDir()
	output := filepath.Join(dir, "not-a-dir")
	writeFile(t, output, "")
	prog := filepath.Join(dir, "p.c")
	wit := filepath.Join(dir, "w.yml")
	writeFile(t, prog, programWithSingleNondet)
	writeFile(t, wit, witnessHitsViolation)
	_, _, err := turnWitnessToTest(wit, prog, dir, output, time.Second)
	if err == nil {
		t.Error("expected error writing instrumented_program.c into a non-directory output")
	}
}

func TestTurnWitnessToTestFailsWritingUnsupportedInstrumented(t *testing.T) {
	dir := t.TempDir()
	output := filepath.Join(dir, "not-a-dir")
	writeFile(t, output, "")
	prog := filepath.Join(dir, "p.c")
	wit := filepath.Join(dir, "w.yml")
	writeFile(t, prog, programWithSingleNondet)
	writeFile(t, wit, witnessAssumptionOnly)
	_, _, err := turnWitnessToTest(wit, prog, dir, output, time.Second)
	if err == nil {
		t.Error("expected error writing the unsupported-witness path")
	}
}

func TestTurnWitnessToTestRejectsMissingWitness(t *testing.T) {
	_, _, err := turnWitnessToTest("/nonexistent.yml", "/nonexistent.c", t.TempDir(), t.TempDir(), time.Second)
	if err == nil {
		t.Error("expected error for missing files")
	}
}

func TestTurnWitnessToTestRejectsMissingProgram(t *testing.T) {
	dir := t.TempDir()
	wit := filepath.Join(dir, "witness.yml")
	writeFile(t, wit, witnessHitsViolation)
	_, _, err := turnWitnessToTest(wit, "/nonexistent.c", dir, dir, time.Second)
	if err == nil {
		t.Error("expected error for missing program")
	}
}

func TestTurnWitnessToTestRejectsMalformedWitness(t *testing.T) {
	dir := t.TempDir()
	wit := filepath.Join(dir, "witness.yml")
	prog := filepath.Join(dir, "program.c")
	writeFile(t, wit, "not: [valid yaml")
	writeFile(t, prog, programWithSingleNondet)
	_, _, err := turnWitnessToTest(wit, prog, dir, dir, time.Second)
	if err == nil {
		t.Error("expected error for malformed witness")
	}
}

func TestRunFullPipelineConfirmed(t *testing.T) {
	dir := t.TempDir()
	prog := filepath.Join(dir, "program.c")
	wit := filepath.Join(dir, "witness.yml")
	out := filepath.Join(dir, "out")
	writeFile(t, prog, programWithSingleNondet)
	writeFile(t, wit, witnessHitsViolation)
	exit, msg := run([]string{"--witness", wit, "--program", prog, "--output", out, "--time-per-run", "5"}, os.Stdout, os.Stderr)
	if exit != 0 {
		t.Errorf("exit=%d msg=%q", exit, msg)
	}
}

func TestRunFailsOnCompileError(t *testing.T) {
	// A program that compiles successfully alone but breaks once instrumented
	// is hard to construct. Instead, use a program with a syntax error: the
	// witness's location must still match, so put the syntax error elsewhere.
	prog := "void reach_error(){}\nextern int __VERIFIER_nondet_int(void);\nint main() {\n  int x = __VERIFIER_nondet_int();\n  this is not C;\n  if (x == 42) reach_error();\n}\n"
	wit := strings.Replace(witnessHitsViolation, "line: 6, column: 5", "line: 6, column: 16", 1)
	dir := t.TempDir()
	progPath := filepath.Join(dir, "program.c")
	witPath := filepath.Join(dir, "witness.yml")
	writeFile(t, progPath, prog)
	writeFile(t, witPath, wit)
	_, _, err := turnWitnessToTest(witPath, progPath, dir, dir, time.Second)
	if err == nil {
		t.Error("expected compile error")
	}
}

func TestRunFullPipelineFailsOnBadWitness(t *testing.T) {
	dir := t.TempDir()
	prog := filepath.Join(dir, "program.c")
	wit := filepath.Join(dir, "witness.yml")
	writeFile(t, prog, programWithSingleNondet)
	writeFile(t, wit, "not: [valid yaml")
	exit, msg := run([]string{"--witness", wit, "--program", prog, "--output", filepath.Join(dir, "out")}, os.Stdout, os.Stderr)
	if exit != 1 {
		t.Errorf("exit=%d msg=%q, want exit=1", exit, msg)
	}
}

func TestTurnWitnessToTestRejectsMismatchedLocation(t *testing.T) {
	prog := programWithSingleNondet
	// Witness names a column that doesn't exist as a call site.
	wit := strings.Replace(witnessHitsViolation, "column: 33", "column: 99", 1)
	dir := t.TempDir()
	progPath := filepath.Join(dir, "program.c")
	witPath := filepath.Join(dir, "witness.yml")
	writeFile(t, progPath, prog)
	writeFile(t, witPath, wit)
	_, _, err := turnWitnessToTest(witPath, progPath, dir, dir, time.Second)
	if err == nil {
		t.Error("expected error for location mismatch")
	}
}
