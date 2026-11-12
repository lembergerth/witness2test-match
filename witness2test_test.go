// This file is part of witness2test-match,
// a tool to turn SV-COMP violation witnesses (format v2) into executable tests.
// https://github.com/lembergerth/witness2test-match
//
// SPDX-FileCopyrightText: 2026 Thomas Lemberger <https://thomaslemberger.com>
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"witness2test/execution"
	"witness2test/property"
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
        constraint: { value: "x >= 42", format: "c_expression" }
        location: { file_name: "program.c", line: 5, column: 3 }
`

func runPipeline(t *testing.T, programSrc, witnessSrc string) (execution.Verdict, string) {
	t.Helper()
	return runPipelineFor(t, programSrc, witnessSrc, "LP64", nil)
}

func runPipelineFor(t *testing.T, programSrc, witnessSrc, model string, properties []property.Property) (execution.Verdict, string) {
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
	v, instPath, err := turnWitnessToTest(wit, prog, dir, out, executionOptions{timeout: 20 * time.Second, model: model, properties: properties})
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
	if v.Status != execution.Confirmed || v.Violated != property.UnreachCall {
		t.Errorf("got %+v, want Confirmed unreach-call", v)
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
	if notes := strings.Join(v.Notes, "\n"); !strings.Contains(notes, "assumption=1") {
		t.Errorf("verdict notes should summarize waypoints, got %q", notes)
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

func TestFormatVerdict(t *testing.T) {
	tests := []struct {
		name    string
		verdict execution.Verdict
		want    string
	}{
		{"confirmed unreach", execution.Verdict{Status: execution.Confirmed, ExitCode: 213, Violated: property.UnreachCall}, "Verdict: Confirmed unreach-call (exit code 213). Instrumented program: /tmp/x.c"},
		{"confirmed subproperty", execution.Verdict{Status: execution.Confirmed, ExitCode: 215, Violated: property.ValidDeref}, "Verdict: Confirmed valid-deref (exit code 215). Instrumented program: /tmp/x.c"},
		{"not confirmed", execution.Verdict{Status: execution.NotConfirmed}, "Verdict: NotConfirmed (exit code 0). Instrumented program: /tmp/x.c"},
		{"inconsistent", execution.Verdict{Status: execution.Inconsistent, ExitCode: 214}, "Verdict: WitnessInconsistent (exit code 214). Instrumented program: /tmp/x.c"},
		{"timeout", execution.Verdict{Status: execution.Timeout, ExitCode: -1}, "Verdict: Timeout (exit code -1). Instrumented program: /tmp/x.c"},
		{"notes and stderr", execution.Verdict{Status: execution.WitnessUnsupported, Notes: []string{"first", "second"}, Stderr: "diagnostic line"}, "Verdict: WitnessUnsupported (exit code 0). Instrumented program: /tmp/x.c\nNote: first\nNote: second\n--- program stderr ---\ndiagnostic line"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatVerdict(tt.verdict, "/tmp/x.c"); got != tt.want {
				t.Errorf("formatVerdict = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestReadProperties(t *testing.T) {
	path := filepath.Join(t.TempDir(), "properties.prp")
	writeFile(t, path, "CHECK(init(main()),LTL(G valid-deref))\nCHECK(init(main()),LTL(G ! overflow))")
	properties, err := readProperties(path)
	want := []property.Property{property.ValidDeref, property.NoOverflow}
	if err != nil || !reflect.DeepEqual(properties, want) {
		t.Errorf("readProperties = %v, %v; want %v, nil", properties, err, want)
	}
	properties, err = readProperties("")
	if err != nil || !reflect.DeepEqual(properties, []property.Property{property.UnreachCall}) {
		t.Errorf("default properties = %v, %v; want [unreach-call], nil", properties, err)
	}
}

func TestRunRejectsInvalidPropertyFiles(t *testing.T) {
	for _, content := range []string{"", "CHECK(init(main()),LTL(G unknown))"} {
		t.Run(content, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "properties.prp")
			writeFile(t, path, content)
			wantMessage := fmt.Sprintf("witness2test-match: property file %q: property file contains no properties", path)
			if content != "" {
				wantMessage = fmt.Sprintf("witness2test-match: property file %q: line 1: unrecognized property expression %q", path, content)
			}
			out := filepath.Join(dir, "out")
			exit, msg := run([]string{"--witness", "unused.yml", "--program", "unused.c", "--property", path, "--output", out}, os.Stdout, os.Stderr)
			if exit != 1 || msg != wantMessage {
				t.Errorf("run = %d, %q; want 1, %q", exit, msg, wantMessage)
			}
			if _, err := os.Stat(out); !os.IsNotExist(err) {
				t.Errorf("output directory exists after invalid property input: %v", err)
			}
		})
	}
}

func TestRunRejectsMissingPropertyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.prp")
	_, readErr := os.ReadFile(path)
	if readErr == nil {
		t.Fatal("expected missing property file")
	}
	exit, msg := run([]string{"--witness", "unused.yml", "--program", "unused.c", "--property", path}, os.Stdout, os.Stderr)
	wantMessage := fmt.Sprintf("witness2test-match: failed to read property file: %v", readErr)
	if exit != 1 || msg != wantMessage {
		t.Errorf("run = %d, %q; want 1, %q", exit, msg, wantMessage)
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

func TestRunReportsVersionWriteError(t *testing.T) {
	stdout := createClosedOutput(t)
	exit, msg := run([]string{"--version"}, stdout, os.Stderr)
	writeErr := &os.PathError{Op: "write", Path: stdout.Name(), Err: os.ErrClosed}
	wantMessage := fmt.Sprintf("witness2test-match: failed to write version: %v", writeErr)
	if exit != 1 || msg != wantMessage {
		t.Errorf("run = %d, %q; want 1, %q", exit, msg, wantMessage)
	}
}

func TestRunReportsVerdictWriteError(t *testing.T) {
	dir := t.TempDir()
	prog := filepath.Join(dir, "program.c")
	wit := filepath.Join(dir, "witness.yml")
	writeFile(t, prog, programWithSingleNondet)
	writeFile(t, wit, witnessHitsViolation)
	stdout := createClosedOutput(t)
	exit, msg := run([]string{"--witness", wit, "--program", prog, "--output", filepath.Join(dir, "out")}, stdout, os.Stderr)
	writeErr := &os.PathError{Op: "write", Path: stdout.Name(), Err: os.ErrClosed}
	wantMessage := fmt.Sprintf("witness2test-match: failed to write verdict: %v", writeErr)
	if exit != 1 || msg != wantMessage {
		t.Errorf("run = %d, %q; want 1, %q", exit, msg, wantMessage)
	}
}

func createClosedOutput(t *testing.T) *os.File {
	t.Helper()
	stdout, err := os.CreateTemp(t.TempDir(), "stdout-")
	if err != nil {
		t.Fatalf("create stdout: %v", err)
	}
	if err := stdout.Close(); err != nil {
		t.Fatalf("close stdout: %v", err)
	}
	return stdout
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

func TestRunRejectsInvalidModel(t *testing.T) {
	for _, model := range []string{"", "ilp32", "lp64", "LLP64", "-m32"} {
		t.Run(model, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "out")
			exit, msg := run([]string{"--witness", "unused.yml", "--program", "unused.c", "--output", out, "--model", model}, os.Stdout, os.Stderr)
			if exit != 2 || msg != "" {
				t.Errorf("run = %d, %q; want 2, empty message", exit, msg)
			}
			if _, err := os.Stat(out); !os.IsNotExist(err) {
				t.Errorf("output directory exists after invalid model: %v", err)
			}
		})
	}
}

func TestRunRejectsMissingModelArgument(t *testing.T) {
	exit, msg := run([]string{"--model"}, os.Stdout, os.Stderr)
	if exit != 2 || msg != "" {
		t.Errorf("run = %d, %q; want 2, empty message", exit, msg)
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
	_, _, err := turnWitnessToTest(wit, prog, dir, output, executionOptions{timeout: time.Second})
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
	_, _, err := turnWitnessToTest(wit, prog, dir, output, executionOptions{timeout: time.Second})
	if err == nil {
		t.Error("expected error writing the unsupported-witness path")
	}
}

func TestTurnWitnessToTestRejectsMissingWitness(t *testing.T) {
	_, _, err := turnWitnessToTest("/nonexistent.yml", "/nonexistent.c", t.TempDir(), t.TempDir(), executionOptions{timeout: time.Second})
	if err == nil {
		t.Error("expected error for missing files")
	}
}

func TestTurnWitnessToTestRejectsMissingProgram(t *testing.T) {
	dir := t.TempDir()
	wit := filepath.Join(dir, "witness.yml")
	writeFile(t, wit, witnessHitsViolation)
	_, _, err := turnWitnessToTest(wit, "/nonexistent.c", dir, dir, executionOptions{timeout: time.Second})
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
	_, _, err := turnWitnessToTest(wit, prog, dir, dir, executionOptions{timeout: time.Second})
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
	_, _, err := turnWitnessToTest(witPath, progPath, dir, dir, executionOptions{timeout: time.Second})
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

// A function_return waypoint that is not on a nondet call provides no input.
func TestTurnWitnessToTestNotesMismatchedLocation(t *testing.T) {
	wit := strings.Replace(witnessHitsViolation, "column: 33", "column: 99", 1)
	v, _ := runPipelineFor(t, programWithSingleNondet, wit, "ILP32", nil)
	if v.Status != execution.WitnessUnsupported {
		t.Fatalf("got %s, want WitnessUnsupported", v.Status)
	}
	want := "function_return at 4:99 (1 value) not matched: no __VERIFIER_nondet_X() call ends at the location"
	if len(v.Notes) != 2 || v.Notes[0] != want {
		t.Errorf("notes = %q, want first note %q", v.Notes, want)
	}
}
