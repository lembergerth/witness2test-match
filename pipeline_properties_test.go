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

var allMemsafety = []property.Property{property.ValidFree, property.ValidDeref, property.ValidMemtrack}

// witnessFor builds a violation witness for program.c with the given
// specification and waypoints (each in the YAML flow form used below).
func witnessFor(specification string, waypoints ...string) string {
	var b strings.Builder
	b.WriteString(`- entry_type: "violation_sequence"
  metadata:
    format_version: "2.1"
    uuid: "00000000-0000-0000-0000-000000000099"
    creation_time: "2026-01-01T00:00:00Z"
    producer: { name: "test", version: "0" }
    task:
      input_files: [ "program.c" ]
      input_file_hashes: { "program.c": "deadbeef" }
`)
	if specification != "" {
		fmt.Fprintf(&b, "      specification: %q\n", specification)
	}
	b.WriteString("      data_model: \"LP64\"\n      language: \"C\"\n  content:\n")
	for _, waypoint := range waypoints {
		fmt.Fprintf(&b, "  - segment:\n    - waypoint: %s\n", waypoint)
	}
	return b.String()
}

func returns(line, column int, value string) string {
	return fmt.Sprintf(`{ type: "function_return", action: "follow", constraint: { value: "\\result == %s", format: "ext_c_expression" }, location: { file_name: "program.c", line: %d, column: %d } }`, value, line, column)
}

func target(line, column int) string {
	return fmt.Sprintf(`{ type: "target", action: "follow", location: { file_name: "program.c", line: %d, column: %d } }`, line, column)
}

func TestResolveCheckedProperties(t *testing.T) {
	tests := []struct {
		name          string
		selected      []property.Property
		specification string
		checked       []property.Property
		note          string
		err           string
	}{
		{"claim equals selection", []property.Property{property.NoOverflow}, "G ! overflow", []property.Property{property.NoOverflow}, "", ""},
		{"claim is subproperty of selection", allMemsafety, "CHECK( init(main()), LTL(G valid-deref) )", []property.Property{property.ValidDeref}, "", ""},
		{"claim of whole memory safety", allMemsafety, "G valid-free\nG valid-deref\nG valid-memtrack", allMemsafety, "", ""},
		{"claim not selected", []property.Property{property.UnreachCall}, "G ! overflow", nil, "",
			"witness claims a violation of no-overflow, which the selected properties (unreach-call) do not include"},
		{"claim partly not selected", []property.Property{property.ValidDeref}, "G valid-free\nG valid-deref", nil, "",
			"witness claims a violation of valid-memsafety(valid-free), which the selected properties (valid-memsafety(valid-deref)) do not include"},
		{"no specification", allMemsafety, "", allMemsafety, "witness states no specification; checking the selected properties", ""},
		{"unknown specification", []property.Property{property.NoOverflow, property.NoOverflow}, "F end", []property.Property{property.NoOverflow},
			`witness specification "F end" is not recognized; checking the selected properties`, ""},
		{"data race claim is kept", []property.Property{property.NoDataRace}, "G ! data-race", []property.Property{property.NoDataRace}, "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checked, notes, err := resolveCheckedProperties(tt.selected, tt.specification)
			if tt.err != "" {
				if err == nil || err.Error() != tt.err {
					t.Fatalf("error = %v, want %q", err, tt.err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(checked, tt.checked) {
				t.Errorf("checked = %v, want %v", checked, tt.checked)
			}
			if got := strings.Join(notes, "|"); got != tt.note {
				t.Errorf("notes = %q, want %q", got, tt.note)
			}
		})
	}
}

const overflowProgram = `extern int __VERIFIER_nondet_int(void);
int main() {
  int x = __VERIFIER_nondet_int();
  int y = 0;
  y = x + 1;
  return y == 0;
}
`

func TestPipelineNoOverflow(t *testing.T) {
	hit := witnessFor("G ! overflow", returns(3, 33, "2147483647"), target(5, 3))
	for _, model := range []string{"LP64", "ILP32"} {
		t.Run(model, func(t *testing.T) {
			v, _ := runPipelineFor(t, overflowProgram, hit, model, []property.Property{property.NoOverflow})
			if v.Status != execution.Confirmed || v.Violated != property.NoOverflow {
				t.Errorf("got %s %q, notes %q, want Confirmed no-overflow\n%s", v.Status, v.Violated, v.Notes, v.Stderr)
			}
		})
	}
	miss := witnessFor("G ! overflow", returns(3, 33, "5"), target(5, 3))
	if v, _ := runPipelineFor(t, overflowProgram, miss, "LP64", []property.Property{property.NoOverflow}); v.Status != execution.NotConfirmed {
		t.Errorf("got %s, want NotConfirmed", v.Status)
	}
}

func TestPipelineRejectsClaimOutsideSelection(t *testing.T) {
	dir := t.TempDir()
	prog := filepath.Join(dir, "program.c")
	wit := filepath.Join(dir, "witness.yml")
	out := filepath.Join(dir, "out")
	writeFile(t, prog, overflowProgram)
	writeFile(t, wit, witnessFor("G ! overflow", returns(3, 33, "2147483647")))
	exit, msg := run([]string{"--witness", wit, "--program", prog, "--output", out}, os.Stdout, os.Stderr)
	want := "witness2test-match: witness claims a violation of no-overflow, which the selected properties (unreach-call) do not include"
	if exit != 1 || msg != want {
		t.Errorf("run = %d, %q; want 1, %q", exit, msg, want)
	}
}

func TestPipelineStopsOnDataRace(t *testing.T) {
	// The program does not even compile: nothing may be compiled or executed.
	program := "this is not C\n"
	v, instPath := runPipelineFor(t, program, witnessFor("G ! data-race", target(1, 1)), "LP64", []property.Property{property.NoDataRace})
	if v.Status != execution.PropertyUnsupported {
		t.Fatalf("got %s, want PropertyUnsupported", v.Status)
	}
	if want := []string{"checking no-data-race is not supported"}; !reflect.DeepEqual(v.Notes, want) {
		t.Errorf("notes = %q, want %q", v.Notes, want)
	}
	if got, _ := os.ReadFile(instPath); string(got) != program {
		t.Error("the program must be emitted unchanged")
	}
}

const derefProgram = `#include <stdlib.h>
int main() {
  int *p = malloc(2 * sizeof(int));
  volatile int index = 2;
  p[index] = 1;
  free(p);
  return 0;
}
`

// A program without nondeterministic calls needs no input values.
func TestPipelineExecutesDeterministicProgram(t *testing.T) {
	for _, model := range []string{"LP64", "ILP32"} {
		t.Run(model, func(t *testing.T) {
			v, _ := runPipelineFor(t, derefProgram, witnessFor("G valid-deref", target(5, 3)), model, allMemsafety)
			if v.Status != execution.Confirmed || v.Violated != property.ValidDeref {
				t.Errorf("got %s %q, notes %q, want Confirmed valid-deref\n%s", v.Status, v.Violated, v.Notes, v.Stderr)
			}
		})
	}
}

func TestPipelineChecksOnlyClaimedSubproperty(t *testing.T) {
	// The execution violates valid-deref, but the witness claims valid-free.
	v, _ := runPipelineFor(t, derefProgram, witnessFor("G valid-free", target(6, 3)), "LP64", allMemsafety)
	if v.Status != execution.NotConfirmed {
		t.Fatalf("got %s, want NotConfirmed", v.Status)
	}
	want := "execution violated valid-memsafety(valid-deref), which is not among the checked properties"
	if !reflect.DeepEqual(v.Notes, []string{want}) {
		t.Errorf("notes = %q, want %q", v.Notes, want)
	}
}

func TestPipelineFallsBackToSelectedProperties(t *testing.T) {
	v, _ := runPipelineFor(t, derefProgram, witnessFor("", target(5, 3)), "LP64", allMemsafety)
	if v.Status != execution.Confirmed || v.Violated != property.ValidDeref {
		t.Errorf("got %s %q, want Confirmed valid-deref", v.Status, v.Violated)
	}
	if len(v.Notes) != 1 || v.Notes[0] != "witness states no specification; checking the selected properties" {
		t.Errorf("notes = %q", v.Notes)
	}
}

const freeProgram = `#include <stdlib.h>
void release(int *p) {
  free(p);
}
int main() {
  int *p = malloc(sizeof(int));
  release(p);
  release(p);
  return 0;
}
`

const memtrackProgram = `#include <stdlib.h>
int main() {
  int *p = malloc(sizeof(int));
  p = 0;
  return p != 0;
}
`

const memcleanupProgram = `#include <stdlib.h>
int *keep;
int main() {
  keep = malloc(sizeof(int));
  return 0;
}
`

func TestPipelineMemoryProperties(t *testing.T) {
	tests := []struct {
		name     string
		program  string
		witness  string
		selected []property.Property
		violated property.Property
	}{
		{"valid-free", freeProgram, witnessFor("G valid-free", target(3, 3)), allMemsafety, property.ValidFree},
		{"valid-memtrack", memtrackProgram, witnessFor("G valid-memtrack", target(4, 3)), allMemsafety, property.ValidMemtrack},
		{"valid-memcleanup", memcleanupProgram, witnessFor("G valid-memcleanup", target(5, 3)), []property.Property{property.ValidMemcleanup}, property.ValidMemcleanup},
	}
	for _, model := range []string{"LP64", "ILP32"} {
		for _, tt := range tests {
			t.Run(model+"/"+tt.name, func(t *testing.T) {
				v, _ := runPipelineFor(t, tt.program, tt.witness, model, tt.selected)
				if v.Status != execution.Confirmed || v.Violated != tt.violated {
					t.Errorf("got %s %q, notes %q, want Confirmed %s\n%s", v.Status, v.Violated, v.Notes, tt.violated, v.Stderr)
				}
			})
		}
	}
}

// reach_error() must only end the test when unreach-call is checked.
func TestPipelineLeavesReachErrorAloneForOtherProperties(t *testing.T) {
	program := `void reach_error() {}
extern int __VERIFIER_nondet_int(void);
int main() {
  int x = __VERIFIER_nondet_int();
  reach_error();
  int y = 0;
  y = x + 1;
  return y == 0;
}
`
	w := witnessFor("G ! overflow", returns(4, 33, "2147483647"), target(7, 3))
	v, _ := runPipelineFor(t, program, w, "LP64", []property.Property{property.NoOverflow, property.UnreachCall})
	if v.Status != execution.Confirmed || v.Violated != property.NoOverflow {
		t.Errorf("got %s %q, want Confirmed no-overflow", v.Status, v.Violated)
	}
}

func TestPipelineTargetLocation(t *testing.T) {
	unreachProgram := `void reach_error() {}
extern int __VERIFIER_nondet_int(void);
int main() {
  int x = __VERIFIER_nondet_int();
  if (x == 1) {
    reach_error();
  }
  if (x == 2) {
    reach_error();
  }
  return 0;
}
`
	unreach := []property.Property{property.UnreachCall}
	overflow := []property.Property{property.NoOverflow}
	tests := []struct {
		name     string
		program  string
		witness  string
		selected []property.Property
		violated property.Property // empty: NotConfirmed
		note     string
	}{
		{"unreach at target", unreachProgram, witnessFor("G ! call(reach_error())", returns(4, 33, "2"), target(9, 5)), unreach, property.UnreachCall, ""},
		{"unreach at other call", unreachProgram, witnessFor("G ! call(reach_error())", returns(4, 33, "1"), target(9, 5)), unreach, "",
			"violation of unreach-call observed at line 6, but the witness's target is at line 9"},
		{"unreach without target", unreachProgram, witnessFor("G ! call(reach_error())", returns(4, 33, "1")), unreach, property.UnreachCall, ""},
		{"overflow at target", overflowProgram, witnessFor("G ! overflow", returns(3, 33, "2147483647"), target(5, 3)), overflow, property.NoOverflow, ""},
		{"overflow elsewhere", overflowProgram, witnessFor("G ! overflow", returns(3, 33, "2147483647"), target(6, 3)), overflow, "",
			"violation of no-overflow observed at line 5, but the witness's target is at line 6"},
		{"deref at target", derefProgram, witnessFor("G valid-deref", target(5, 3)), allMemsafety, property.ValidDeref, ""},
		{"deref elsewhere", derefProgram, witnessFor("G valid-deref", target(3, 3)), allMemsafety, "",
			"violation of valid-memsafety(valid-deref) observed at line 5, but the witness's target is at line 3"},
		{"free at target", freeProgram, witnessFor("G valid-free", target(3, 3)), allMemsafety, property.ValidFree, ""},
		{"free elsewhere", freeProgram, witnessFor("G valid-free", target(8, 3)), allMemsafety, "",
			"violation of valid-memsafety(valid-free) observed at line 3, but the witness's target is at line 8"},
		// The reports for these two properties do not name the violating statement.
		{"memtrack target is not checked", memtrackProgram, witnessFor("G valid-memtrack", target(1, 1)), allMemsafety, property.ValidMemtrack, ""},
		{"memcleanup target is not checked", memcleanupProgram, witnessFor("G valid-memcleanup", target(1, 1)), []property.Property{property.ValidMemcleanup}, property.ValidMemcleanup, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, _ := runPipelineFor(t, tt.program, tt.witness, "LP64", tt.selected)
			wantStatus := execution.Confirmed
			if tt.violated == "" {
				wantStatus = execution.NotConfirmed
			}
			if v.Status != wantStatus || v.Violated != tt.violated {
				t.Errorf("got %s %q, want %s %q\nnotes: %q\n%s", v.Status, v.Violated, wantStatus, tt.violated, v.Notes, v.Stderr)
			}
			if got := strings.Join(v.Notes, "|"); got != tt.note {
				t.Errorf("notes = %q, want %q", got, tt.note)
			}
		})
	}
}

// Physical lines count for the target check, whatever linemarkers say.
func TestPipelineTargetLocationIgnoresLinemarkers(t *testing.T) {
	program := "# 1 \"original.c\"\n# 300 \"header.h\" 3 4\n" + strings.Replace(overflowProgram, "int main() {", "#line 77\nint main() {", 1)
	w := witnessFor("G ! overflow", returns(6, 33, "2147483647"), target(8, 3))
	v, _ := runPipelineFor(t, program, w, "LP64", []property.Property{property.NoOverflow})
	if v.Status != execution.Confirmed || v.Violated != property.NoOverflow {
		t.Errorf("got %s %q, notes %q, want Confirmed no-overflow\n%s", v.Status, v.Violated, v.Notes, v.Stderr)
	}
}

func TestPipelineAssumptionProvidesInput(t *testing.T) {
	assumption := `{ type: "assumption", action: "follow", constraint: { value: "x == 42", format: "c_expression" }, location: { file_name: "program.c", line: 5, column: 3 } }`
	v, _ := runPipeline(t, programWithSingleNondet, witnessFor("G ! call(reach_error())", assumption, target(6, 5)))
	if v.Status != execution.Confirmed || v.Violated != property.UnreachCall {
		t.Errorf("got %s %q, notes %q, want Confirmed unreach-call", v.Status, v.Violated, v.Notes)
	}
}

func TestPipelineBranchingProvidesInput(t *testing.T) {
	program := `void reach_error() {}
extern int __VERIFIER_nondet_int(void);
int main() {
  int count = 0;
  while (__VERIFIER_nondet_int() > 0) {
    count++;
  }
  if (count == 2) {
    reach_error();
  }
  return 0;
}
`
	branch := func(value string) string {
		return fmt.Sprintf(`{ type: "branching", action: "follow", constraint: { value: "%s" }, location: { file_name: "program.c", line: 5, column: 3 } }`, value)
	}
	v, _ := runPipeline(t, program, witnessFor("G ! call(reach_error())", branch("true"), branch("true"), branch("false"), target(9, 5)))
	if v.Status != execution.Confirmed || v.Violated != property.UnreachCall {
		t.Errorf("got %s %q, notes %q, want Confirmed unreach-call", v.Status, v.Violated, v.Notes)
	}
	v, _ = runPipeline(t, program, witnessFor("G ! call(reach_error())", branch("true"), branch("false"), target(9, 5)))
	if v.Status != execution.NotConfirmed {
		t.Errorf("got %s, want NotConfirmed", v.Status)
	}
}

func TestLimitNotes(t *testing.T) {
	var notes []string
	for i := 0; i < maxPrintedNotes+3; i++ {
		notes = append(notes, fmt.Sprint("note ", i))
	}
	limited := limitNotes(notes)
	if len(limited) != maxPrintedNotes+1 || limited[maxPrintedNotes] != "... and 3 more waypoints that were not matched" {
		t.Errorf("limited = %q", limited)
	}
	if got := limitNotes(notes[:2]); !reflect.DeepEqual(got, notes[:2]) {
		t.Errorf("short list changed: %q", got)
	}
}

func TestPipelineTimeoutStillReported(t *testing.T) {
	dir := t.TempDir()
	prog := filepath.Join(dir, "program.c")
	wit := filepath.Join(dir, "witness.yml")
	writeFile(t, prog, "int main() { for (;;) {} return 0; }\n")
	writeFile(t, wit, witnessFor("G ! overflow", target(1, 14)))
	v, _, err := turnWitnessToTest(wit, prog, dir, dir, executionOptions{timeout: 300 * time.Millisecond, properties: []property.Property{property.NoOverflow}})
	if err != nil || v.Status != execution.Timeout {
		t.Errorf("got %s, %v; want Timeout", v.Status, err)
	}
}

// INT_MIN % -1 is reported by the sanitizer like INT_MIN / -1, but the
// remainder is not an operation that no-overflow covers.
func TestPipelineRemainderIsNoOverflow(t *testing.T) {
	program := `extern int __VERIFIER_nondet_int(void);
int main() {
  int x = __VERIFIER_nondet_int();
  volatile int minusOne = -1;
  int r = 0;
  r = x % minusOne;
  return r;
}
`
	w := witnessFor("G ! overflow", returns(3, 33, "-2147483648"), target(6, 3))
	v, _ := runPipelineFor(t, program, w, "LP64", []property.Property{property.NoOverflow})
	if v.Status != execution.NotConfirmed {
		t.Fatalf("got %s %q, want NotConfirmed\n%s", v.Status, v.Violated, v.Stderr)
	}
	want := "the reported overflow is in a remainder operation, which no-overflow does not cover"
	if len(v.Notes) != 1 || v.Notes[0] != want {
		t.Errorf("notes = %q, want %q", v.Notes, want)
	}
	division := strings.Replace(program, "x % minusOne", "x / minusOne", 1)
	if v, _ := runPipelineFor(t, division, w, "LP64", []property.Property{property.NoOverflow}); v.Status != execution.Confirmed {
		t.Errorf("division: got %s, want Confirmed", v.Status)
	}
}

func TestPipelineRejectsWitnessWithoutViolationSequence(t *testing.T) {
	correctness := `- entry_type: "invariant_set"
  metadata:
    format_version: "2.0"
    task:
      specification: "G valid-deref"
  content: []
`
	for name, content := range map[string]string{"correctness witness": correctness, "empty list": "[]\n"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			prog := filepath.Join(dir, "program.c")
			wit := filepath.Join(dir, "witness.yml")
			writeFile(t, prog, derefProgram)
			writeFile(t, wit, content)
			_, _, err := turnWitnessToTest(wit, prog, dir, dir, executionOptions{timeout: time.Second, properties: allMemsafety})
			want := "witness parse: the witness contains no violation_sequence entry"
			if err == nil || err.Error() != want {
				t.Errorf("error = %v, want %q", err, want)
			}
		})
	}
}

func TestPipelineNotesDataModelMismatch(t *testing.T) {
	// witnessFor states data_model LP64.
	v, _ := runPipelineFor(t, derefProgram, witnessFor("G valid-deref", target(5, 3)), "ILP32", allMemsafety)
	want := "witness states data model LP64, but the test is built for ILP32 (--model)"
	if len(v.Notes) != 1 || v.Notes[0] != want {
		t.Errorf("notes = %q, want %q", v.Notes, want)
	}
	if v, _ := runPipelineFor(t, derefProgram, witnessFor("G valid-deref", target(5, 3)), "LP64", allMemsafety); len(v.Notes) != 0 {
		t.Errorf("unexpected notes: %q", v.Notes)
	}
}

// The sanitizers report the line of the operation; the target names the
// start of the statement.
func TestPipelineTargetLocationOfMultiLineStatement(t *testing.T) {
	program := `extern int __VERIFIER_nondet_int(void);
int id(int a) { return a; }
int main() {
  int x = __VERIFIER_nondet_int();
  int y = 0;
  y = id(1) +
    id(x
      + 1);
  int z = 0;
  z = y;
  return z == 0;
}
`
	// The overflow is reported on line 7; the statement starts on line 6.
	overflow := []property.Property{property.NoOverflow}
	for _, tt := range []struct {
		name       string
		targetLine int
		confirmed  bool
	}{
		{"start of the statement", 6, true},
		{"reported line", 7, true},
		{"previous statement", 5, false},
		{"after the reported line", 8, false},
		{"next statement", 9, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			w := witnessFor("G ! overflow", returns(4, 33, "2147483647"), target(tt.targetLine, 3))
			v, _ := runPipelineFor(t, program, w, "LP64", overflow)
			if (v.Status == execution.Confirmed) != tt.confirmed {
				t.Errorf("got %s, notes %q; want confirmed = %v\n%s", v.Status, v.Notes, tt.confirmed, v.Stderr)
			}
		})
	}
}

func TestStatementSpans(t *testing.T) {
	lines := strings.Split("a = 1;\nb =\n  c\n  + d;\nif (x) {\n  y = 1; }\nfor (i = 0;\n     i < 3; i++)\n", "\n")
	for _, tt := range []struct {
		from, to int
		want     bool
	}{
		{2, 2, true}, {2, 3, true}, {2, 4, true},
		{1, 2, false}, {2, 5, false}, {5, 6, false},
		{7, 8, false}, // a ';' ends the search even inside a for header
		{4, 2, false}, {0, 1, false}, {2, 99, false},
	} {
		if got := statementSpans(lines, tt.from, tt.to); got != tt.want {
			t.Errorf("statementSpans(%d, %d) = %v, want %v", tt.from, tt.to, got, tt.want)
		}
	}
}

// The data model must reach the instrumenter: whether a value exists for a
// comparison depends on the size of long.
func TestPipelineModelReachesInstrumenter(t *testing.T) {
	program := `void reach_error() {}
extern long __VERIFIER_nondet_long(void);
int main() {
  if (__VERIFIER_nondet_long() > 2147483647) {
    reach_error();
  }
  return 0;
}
`
	branch := `{ type: "branching", action: "follow", constraint: { value: "true" }, location: { file_name: "program.c", line: 4, column: 3 } }`
	w := witnessFor("G ! call(reach_error())", branch, target(5, 5))
	if v, _ := runPipelineFor(t, program, w, "LP64", nil); v.Status != execution.Confirmed {
		t.Errorf("LP64: got %s, want Confirmed", v.Status)
	}
	// With a 32-bit long no value makes the condition true.
	if v, _ := runPipelineFor(t, program, w, "ILP32", nil); v.Status != execution.WitnessUnsupported {
		t.Errorf("ILP32: got %s, want WitnessUnsupported", v.Status)
	}
}

// Only the checks for the claimed properties are compiled in: here the
// address sanitizer would stop the test at the out-of-bounds read, before
// the overflow.
func TestPipelineCompilesOnlyClaimedChecks(t *testing.T) {
	program := `#include <stdlib.h>
extern int __VERIFIER_nondet_int(void);
int main() {
  int x = __VERIFIER_nondet_int();
  int *p = malloc(4 * sizeof(int));
  volatile int index = 4;
  volatile int beyond = p[index];
  int y = 0;
  y = x + 1;
  return y == 0;
}
`
	w := witnessFor("G ! overflow", returns(4, 33, "2147483647"), target(9, 3))
	v, _ := runPipelineFor(t, program, w, "LP64", []property.Property{property.ValidDeref, property.NoOverflow})
	if v.Status != execution.Confirmed || v.Violated != property.NoOverflow {
		t.Errorf("got %s %q, notes %q; want Confirmed no-overflow\n%s", v.Status, v.Violated, v.Notes, v.Stderr)
	}
}

// Whether a property is supported matters only for claimed properties.
func TestPipelineIgnoresUnsupportedSelectedProperty(t *testing.T) {
	w := witnessFor("G ! overflow", returns(3, 33, "2147483647"), target(5, 3))
	v, _ := runPipelineFor(t, overflowProgram, w, "LP64", []property.Property{property.NoDataRace, property.NoOverflow})
	if v.Status != execution.Confirmed || v.Violated != property.NoOverflow {
		t.Errorf("got %s %q, want Confirmed no-overflow", v.Status, v.Violated)
	}
}

func TestPipelineReportsUnmatchedWaypoints(t *testing.T) {
	program := `void reach_error() {}
extern int __VERIFIER_nondet_int(void);
int main() {
  int x = __VERIFIER_nondet_int();
  int y = 0;
  if (x == 42 && y == 0) {
    reach_error();
  }
  return 0;
}
`
	late := `{ type: "assumption", action: "follow", constraint: { value: "x == 42", format: "c_expression" }, location: { file_name: "program.c", line: 6, column: 3 } }`
	v, _ := runPipeline(t, program, witnessFor("", returns(4, 33, "42"), late, target(7, 5)))
	if v.Status != execution.Confirmed {
		t.Fatalf("got %s, want Confirmed", v.Status)
	}
	if len(v.Notes) != 2 || v.Notes[0] != "witness states no specification; checking the selected properties" ||
		!strings.HasPrefix(v.Notes[1], "assumption at 6:3 (x == 42) not matched: ") {
		t.Errorf("notes = %q", v.Notes)
	}
}

// A reach_error() call in a macro happens where the macro is used.
func TestPipelineTargetOfReachErrorInMacro(t *testing.T) {
	program := `void reach_error() {}
#define FAIL() reach_error()
extern int __VERIFIER_nondet_int(void);
int main() {
  int x = __VERIFIER_nondet_int();
  if (x == 42) {
    FAIL();
  }
  return 0;
}
`
	w := witnessFor("G ! call(reach_error())", returns(5, 33, "42"), target(7, 5))
	v, _ := runPipeline(t, program, w)
	if v.Status != execution.Confirmed {
		t.Errorf("got %s, notes %q; want Confirmed", v.Status, v.Notes)
	}
}
