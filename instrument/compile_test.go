// This file is part of witness2test-match,
// a tool to turn SV-COMP violation witnesses (format v2) into executable tests.
// https://github.com/lembergerth/witness2test-match
//
// SPDX-FileCopyrightText: 2026 Thomas Lemberger <https://thomaslemberger.com>
//
// SPDX-License-Identifier: Apache-2.0

package instrument

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"witness2test/harness"
	"witness2test/witness"
)

// The tests in this file compile instrumented programs with gcc and run them.
// They are skipped if gcc is not available.

func requireGCC(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("gcc"); err != nil {
		t.Skip("gcc not found")
	}
}

// require32Bit skips the test if gcc cannot build programs for ILP32.
func require32Bit(t *testing.T) {
	t.Helper()
	requireGCC(t)
	probe := exec.Command("gcc", "-m32", "-x", "c", "-", "-o", filepath.Join(t.TempDir(), "probe"))
	probe.Stdin = strings.NewReader("#include <unistd.h>\nint main(void) { return 0; }\n")
	if err := probe.Run(); err != nil {
		t.Skip("gcc cannot build 32-bit programs")
	}
}

// writeProgram writes source and the embedded harness into a fresh directory
// and returns the directory. The program is always named program.c.
func writeProgram(t *testing.T, source string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "program.c"), []byte(source), 0o644); err != nil {
		t.Fatalf("write program: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "harness.c"), []byte(harness.Content()), 0o644); err != nil {
		t.Fatalf("write harness: %v", err)
	}
	return dir
}

// compileAndRun builds source together with the harness and executes it.
// It returns the exit code and what the program wrote to stderr.
func compileAndRun(t *testing.T, source string, gccArgs ...string) (exitCode int, stderr string) {
	t.Helper()
	requireGCC(t)
	dir := writeProgram(t, source)
	binary := filepath.Join(dir, "program")
	args := append([]string{"-std=gnu11", "-o", binary}, gccArgs...)
	args = append(args, "program.c", "harness.c")
	compile := exec.Command("gcc", args...)
	compile.Dir = dir
	if out, err := compile.CombinedOutput(); err != nil {
		t.Fatalf("gcc failed: %v\n%s\nsource:\n%s", err, out, source)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	run := exec.CommandContext(ctx, binary)
	var errBuf bytes.Buffer
	run.Stderr = &errBuf
	err := run.Run()
	var exitErr *exec.ExitError
	switch {
	case err == nil:
		return 0, errBuf.String()
	case errors.As(err, &exitErr) && exitErr.ExitCode() >= 0:
		return exitErr.ExitCode(), errBuf.String()
	}
	t.Fatalf("running the program failed: %v\nstderr:\n%s\nsource:\n%s", err, errBuf.String(), source)
	return -1, ""
}

func mustInstrument(t *testing.T, source string, w *witness.Witness, opts Options) Result {
	t.Helper()
	res, err := InstrumentWitness(source, w, opts)
	if err != nil {
		t.Fatalf("InstrumentWitness: %v", err)
	}
	return res
}

// lines joins the lines of a test program; line i of the program is argument i.
func lines(l ...string) string {
	return strings.Join(l, "\n") + "\n"
}

func TestCompiledProgramReportsPhysicalLines(t *testing.T) {
	// Line 7 returns __LINE__. The linemarker on line 3 would make it 104.
	src := lines(
		"extern int __VERIFIER_nondet_int(void);", // 1
		"int main(void) {",                        // 2
		"# 100 \"foo.h\"",                         // 3
		"  int x = __VERIFIER_nondet_int();",      // 4
		"#line 500",                               // 5
		"  if (x != 42) { return 1; }",            // 6
		"  return __LINE__;",                      // 7
		"}",                                       // 8
	)
	t.Run("original program reports presumed lines", func(t *testing.T) {
		// Sanity check of the test itself.
		if code, _ := compileAndRun(t, strings.Replace(src, "x != 42", "x != 0", 1)); code == 7 {
			t.Fatalf("exit code %d: the linemarkers of the test program have no effect", code)
		}
	})
	t.Run("with generated definitions", func(t *testing.T) {
		w := &witness.Witness{Points: []witness.InjectionPoint{{Loc: witness.Location{Line: 4, Column: 33}, Value: "42"}}}
		res := mustInstrument(t, src, w, Options{RewriteReachError: true})
		if res.InjectedSites != 1 {
			t.Fatalf("InjectedSites = %d, want 1", res.InjectedSites)
		}
		if code, stderr := compileAndRun(t, res.Source); code != 7 {
			t.Errorf("exit code %d, want 7 (__LINE__ of the original line)\nstderr: %s\nsource:\n%s", code, stderr, res.Source)
		}
	})
	t.Run("without generated definitions", func(t *testing.T) {
		res := mustInstrument(t, strings.Replace(src, "x != 42", "x != 0", 1), &witness.Witness{}, Options{})
		if code, stderr := compileAndRun(t, res.Source); code != 7 {
			t.Errorf("exit code %d, want 7 (__LINE__ of the original line)\nstderr: %s\nsource:\n%s", code, stderr, res.Source)
		}
	})
	t.Run("with the old entry point", func(t *testing.T) {
		out, err := Instrument(src, map[witness.Location][]string{{Line: 4, Column: 33}: {"42"}}, CollectNondetCalls(src), nil)
		if err != nil {
			t.Fatalf("Instrument: %v", err)
		}
		if code, stderr := compileAndRun(t, out); code != 7 {
			t.Errorf("exit code %d, want 7\nstderr: %s\nsource:\n%s", code, stderr, out)
		}
	})
}

func TestCompilerDiagnosticsUsePhysicalLines(t *testing.T) {
	requireGCC(t)
	src := lines(
		"extern int __VERIFIER_nondet_int(void);", // 1
		"# 1 \"/usr/include/foo.h\" 1 3 4",        // 2
		"int main(void) {",                        // 3
		"# 77 \"bar.c\"",                          // 4
		"  int x = __VERIFIER_nondet_int();",      // 5
		"  int unused_variable_on_line_6;",        // 6
		"  return x;",                             // 7
		"}",                                       // 8
	)
	w := &witness.Witness{Points: []witness.InjectionPoint{{Loc: witness.Location{Line: 5, Column: 33}, Value: "1"}}}
	res := mustInstrument(t, src, w, Options{})
	dir := writeProgram(t, res.Source)
	cmd := exec.Command("gcc", "-std=gnu11", "-Wall", "-fsyntax-only", "program.c")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("gcc failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "program.c:6:") || !strings.Contains(string(out), "unused_variable_on_line_6") {
		t.Errorf("the warning should be reported for program.c:6, got:\n%s", out)
	}
	if strings.Contains(string(out), "foo.h") || strings.Contains(string(out), "bar.c") {
		t.Errorf("diagnostics must not use the presumed file names of the linemarkers:\n%s", out)
	}
}

func TestCompiledReachErrorWrapper(t *testing.T) {
	tests := []struct {
		name       string
		src        string
		rewrite    bool
		wantCode   int
		wantStderr string
	}{
		{
			name: "single-digit line",
			src: lines(
				"extern void reach_error(void);", // 1
				"int main(void) {",               // 2
				"  reach_error();",               // 3
				"  return 0;",                    // 4
				"}",                              // 5
			),
			rewrite:    true,
			wantCode:   213,
			wantStderr: "witness2test-match: reach_error called at line 3\n",
		},
		{
			name: "multi-digit line behind a linemarker",
			src: lines(
				"void reach_error(void) { }", // 1
				"# 4000 \"elsewhere.c\"",     // 2
				"", "", "", "", "", "", "",   // 3-9
				"int main(void) {",            // 10
				"  if (0) { reach_error(); }", // 11
				"  reach_error();",            // 12
				"  return 0;",                 // 13
				"}",                           // 14
			),
			rewrite:    true,
			wantCode:   213,
			wantStderr: "witness2test-match: reach_error called at line 12\n",
		},
		{
			name: "three-digit line",
			src:  strings.Repeat("\n", 122) + "extern void reach_error(void);\nint main(void) { reach_error(); return 0; }\n",

			rewrite:    true,
			wantCode:   213,
			wantStderr: "witness2test-match: reach_error called at line 124\n",
		},
		{
			name: "program with its own reach_error definition is still stopped",
			src: lines(
				"void reach_error(void) { }",      // 1
				"int main(void) {",                // 2
				"  reach_error();", "  return 0;", // 3, 4
				"}",
			),
			rewrite:    true,
			wantCode:   213,
			wantStderr: "witness2test-match: reach_error called at line 3\n",
		},
		{
			// SV-COMP programs (busybox, coreutils) define write() as a stub.
			name: "program with its own write definition",
			src: lines(
				"extern void reach_error(void);",                                     // 1
				"long write(int fd, const void *buf, unsigned long n) { return 0; }", // 2
				"int main(void) {", // 3
				"  reach_error();", // 4
				"  return 0;",      // 5
				"}",                // 6
			),
			rewrite:    true,
			wantCode:   213,
			wantStderr: "witness2test-match: reach_error called at line 4\n",
		},
		{
			// The violation happens where the macro is expanded, not where
			// it is defined.
			name: "call in a macro reports the line of the expansion",
			src: lines(
				"extern void reach_error(void);", // 1
				"#define FAIL() reach_error()",   // 2
				"int main(void) {",               // 3
				"  int x = 1;",                   // 4
				"  if (x) {",                     // 5
				"    FAIL();",                    // 6
				"  }",                            // 7
				"  return 0;",                    // 8
				"}",                              // 9
			),
			rewrite:    true,
			wantCode:   213,
			wantStderr: "witness2test-match: reach_error called at line 6\n",
		},
		{
			name: "call in a multi-line macro behind a linemarker reports the physical line of the expansion",
			src: lines(
				"extern void reach_error(void);",       // 1
				"#define CHECK(c) do { if (!(c)) { \\", // 2
				"    reach_error(); } } while (0)",     // 3
				"# 700 \"elsewhere.h\"",                // 4
				"int main(void) {",                     // 5
				"  CHECK(1);",                          // 6
				"  CHECK(0);",                          // 7
				"  return 0;",                          // 8
				"}",                                    // 9
			),
			rewrite:    true,
			wantCode:   213,
			wantStderr: "witness2test-match: reach_error called at line 7\n",
		},
		{
			name: "not rewritten: the reach_error of the harness is called",
			src: lines(
				"extern void reach_error(void);", // 1
				"int main(void) {",               // 2
				"  reach_error();",               // 3
				"  return 0;",                    // 4
				"}",                              // 5
			),
			rewrite:    false,
			wantCode:   213,
			wantStderr: "",
		},
		{
			name: "not rewritten: the reach_error of the program is called",
			src: lines(
				"void reach_error(void) { }", // 1
				"int main(void) {",           // 2
				"  reach_error();",           // 3
				"  return 9;",                // 4
				"}",                          // 5
			),
			rewrite:    false,
			wantCode:   9,
			wantStderr: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := mustInstrument(t, tt.src, &witness.Witness{}, Options{RewriteReachError: tt.rewrite})
			code, stderr := compileAndRun(t, res.Source)
			if code != tt.wantCode {
				t.Errorf("exit code %d, want %d", code, tt.wantCode)
			}
			// What the harness prints is not the business of this package.
			if tt.rewrite && stderr != tt.wantStderr {
				t.Errorf("stderr %q, want %q", stderr, tt.wantStderr)
			}
			if !tt.rewrite && strings.Contains(stderr, "reach_error called at line") {
				t.Errorf("stderr %q: the wrapper must not be called", stderr)
			}
		})
	}
}

// The line that the wrapper reports is the physical line of the call, also
// if the call comes from a macro and if there are generated definitions of
// injection functions in front of the program.
func TestCompiledReachErrorInMacroWithInjection(t *testing.T) {
	src := lines(
		"extern int __VERIFIER_nondet_int(void);", // 1
		"extern void reach_error(void);",          // 2
		"#define FAIL() reach_error()",            // 3
		"# 90 \"other.c\"",                        // 4
		"int main(void) {",                        // 5
		"  int x = __VERIFIER_nondet_int();",      // 6
		"  if (x == 42) {",                        // 7
		"    FAIL();",                             // 8
		"  }",                                     // 9
		"  return 0;",                             // 10
		"}",                                       // 11
	)
	w := &witness.Witness{Points: []witness.InjectionPoint{{Loc: witness.Location{Line: 6, Column: 33}, Value: "42"}}}
	res := mustInstrument(t, src, w, Options{RewriteReachError: true})
	code, stderr := compileAndRun(t, res.Source)
	if code != 213 {
		t.Errorf("exit code %d, want 213", code)
	}
	if want := "witness2test-match: reach_error called at line 8\n"; stderr != want {
		t.Errorf("stderr %q, want %q\nsource:\n%s", stderr, want, res.Source)
	}
}

// The values true and false of a witness must end up in the generated C code
// in a form that compiles without <stdbool.h>: the test programs are built
// with -std=gnu11, where true and false are not keywords.
func TestCompiledBooleanLiterals(t *testing.T) {
	src := lines(
		"extern _Bool __VERIFIER_nondet_bool(void);", // 1
		"int main(void) {",                           // 2
		"  _Bool a = __VERIFIER_nondet_bool();",      // 3
		"  _Bool b = __VERIFIER_nondet_bool();",      // 4
		"  return 10 + (a ? 2 : 0) + (b ? 1 : 0);",   // 5
		"}", // 6
	)
	tests := []struct {
		functionReturn string // constraint of the function_return waypoint for a
		assumption     string // constraint of the assumption waypoint for b
		wantCode       int
	}{
		{functionReturn: `\\result == true`, assumption: "b == false", wantCode: 12},
		{functionReturn: `\\result == false`, assumption: "b == true", wantCode: 11},
		{functionReturn: `\\result == true`, assumption: "true == b", wantCode: 13},
		{functionReturn: `\\result == false`, assumption: "(false == b)", wantCode: 10},
	}
	for _, tt := range tests {
		t.Run(tt.functionReturn+", "+tt.assumption, func(t *testing.T) {
			yaml := "- entry_type: violation_sequence\n" +
				"  content:\n" +
				"  - segment:\n" +
				"    - waypoint: { type: function_return, action: follow, constraint: { value: \"" + tt.functionReturn + "\" },\n" +
				"        location: { file_name: program.c, line: 3, column: 36 } }\n" +
				"  - segment:\n" +
				"    - waypoint: { type: assumption, action: follow, constraint: { value: \"" + tt.assumption + "\" },\n" +
				"        location: { file_name: program.c, line: 5, column: 3 } }\n"
			w, err := witness.ParseWitness([]byte(yaml), "program.c")
			if err != nil {
				t.Fatalf("ParseWitness: %v", err)
			}
			if len(w.Points) != 1 || len(w.Assumptions) != 1 {
				t.Fatalf("witness has %d function_return values and %d assumptions, want 1 and 1", len(w.Points), len(w.Assumptions))
			}
			res := mustInstrument(t, src, w, Options{})
			if res.InjectedSites != 2 || len(res.Notes) != 0 {
				t.Fatalf("InjectedSites = %d, notes %q; want 2 sites and no notes", res.InjectedSites, res.Notes)
			}
			if code, stderr := compileAndRun(t, res.Source); code != tt.wantCode {
				t.Errorf("exit code %d, want %d\nstderr: %s\nsource:\n%s", code, tt.wantCode, stderr, res.Source)
			}
		})
	}
}

// The generated declarations must not conflict with the ones of the C
// library, which a preprocessed program contains, in either data model.
func TestGeneratedDeclarationsAgreeWithLibc(t *testing.T) {
	src := lines(
		"#include <unistd.h>",
		"#include <stdlib.h>",
		"extern int __VERIFIER_nondet_int(void);",
		"extern void reach_error(void);",
		"int main(void) {",
		"  int x = __VERIFIER_nondet_int();",
		"  if (x == 5) { reach_error(); }",
		"  return 0;",
		"}",
	)
	w := &witness.Witness{Points: []witness.InjectionPoint{{Loc: witness.Location{Line: 6, Column: 33}, Value: "5"}}}
	for _, model := range []string{"LP64", "ILP32"} {
		t.Run(model, func(t *testing.T) {
			requireGCC(t)
			var gccArgs []string
			if model == "ILP32" {
				require32Bit(t)
				gccArgs = []string{"-m32"}
			}
			res := mustInstrument(t, src, w, Options{RewriteReachError: true, Model: model})
			code, stderr := compileAndRun(t, res.Source, gccArgs...)
			if code != 213 || stderr != "witness2test-match: reach_error called at line 7\n" {
				t.Errorf("exit code %d, stderr %q", code, stderr)
			}
		})
	}
}

func TestCompiledNondetOverflowWithProgramWrite(t *testing.T) {
	src := lines(
		"extern int __VERIFIER_nondet_int(void);",                            // 1
		"long write(int fd, const void *buf, unsigned long n) { return 0; }", // 2
		"int main(void) {",                     // 3
		"  for (int i = 0; i < 2; i++) {",      // 4
		"    int x = __VERIFIER_nondet_int();", // 5
		"  }",                                  // 6
		"  return 0;",                          // 7
		"}",                                    // 8
	)
	w := &witness.Witness{Points: []witness.InjectionPoint{{Loc: witness.Location{Line: 5, Column: 35}, Value: "1"}}}
	res := mustInstrument(t, src, w, Options{})
	code, stderr := compileAndRun(t, res.Source)
	if code != 214 || stderr != "witness2test-match: nondet overflow at 5:35\n" {
		t.Errorf("exit code %d, stderr %q", code, stderr)
	}
}

// The programs of TestCompiledBranching define the nondet functions
// themselves, with return values that lead away from the expected outcome.
// Hence, the expected exit code is only reached with the injected values.
func TestCompiledBranching(t *testing.T) {
	functionReturn := func(line, column int, values ...string) []witness.InjectionPoint {
		var points []witness.InjectionPoint
		for _, v := range values {
			points = append(points, witness.InjectionPoint{Loc: witness.Location{Line: line, Column: column}, Value: v})
		}
		return points
	}
	branches := func(line, column int, values ...string) []witness.Branching {
		var branchings []witness.Branching
		for _, v := range values {
			branchings = append(branchings, branch(line, column, v))
		}
		return branchings
	}
	tests := []struct {
		name         string
		src          string
		w            *witness.Witness
		gccArgs      []string
		wantInjected int
		wantNote     string // substring of the only note, "" if no note is expected
		wantExit     int
		wantStderr   string // substring
	}{
		{
			name: "if taken",
			src: lines(
				"int __VERIFIER_nondet_int(void) { return 0; }", // 1
				"int main(void) {",                 // 2
				"  if (__VERIFIER_nondet_int()) {", // 3
				"    return 11;",                   // 4
				"  }",                              // 5
				"  return 22;",                     // 6
				"}",                                // 7
			),
			w:            &witness.Witness{Branchings: branches(3, 3, "true")},
			wantInjected: 1,
			wantExit:     11,
		},
		{
			name: "if not taken",
			src: lines(
				"int __VERIFIER_nondet_int(void) { return 77; }", // 1
				"int main(void) {",                 // 2
				"  if (__VERIFIER_nondet_int()) {", // 3
				"    return 11;",                   // 4
				"  }",                              // 5
				"  return 22;",                     // 6
				"}",                                // 7
			),
			w:            &witness.Witness{Branchings: branches(3, 3, "false")},
			wantInjected: 1,
			wantExit:     22,
		},
		{
			name: "negated condition",
			src: lines(
				"_Bool __VERIFIER_nondet_bool(void) { return 1; }", // 1
				"int main(void) {",                   // 2
				"  if (!__VERIFIER_nondet_bool()) {", // 3
				"    return 11;",                     // 4
				"  }",                                // 5
				"  return 22;",                       // 6
				"}",                                  // 7
			),
			w:            &witness.Witness{Branchings: branches(3, 0, "true")},
			wantInjected: 1,
			wantExit:     11,
		},
		{
			name: "while taken twice, then left",
			src: lines(
				"int __VERIFIER_nondet_int(void) { return 0; }", // 1
				"int main(void) {", // 2
				"  int n = 0;",     // 3
				"  while (__VERIFIER_nondet_int() > 0) {", // 4
				"    n++;",    // 5
				"  }",         // 6
				"  return n;", // 7
				"}",           // 8
			),
			w:            &witness.Witness{Branchings: branches(4, 3, "true", "true", "false")},
			wantInjected: 1,
			wantExit:     2,
		},
		{
			name: "while evaluated more often than the witness says",
			src: lines(
				"int __VERIFIER_nondet_int(void) { return 0; }", // 1
				"int main(void) {", // 2
				"  int n = 0;",     // 3
				"  while (__VERIFIER_nondet_int() > 0) {", // 4
				"    n++;",    // 5
				"  }",         // 6
				"  return n;", // 7
				"}",           // 8
			),
			w:            &witness.Witness{Branchings: branches(4, 3, "true", "true")},
			wantInjected: 1,
			wantExit:     214,
			wantStderr:   "nondet overflow at 4:32",
		},
		{
			name: "for",
			src: lines(
				"int __VERIFIER_nondet_int(void) { return 3; }", // 1
				"int main(void) {", // 2
				"  int n = 0;",     // 3
				"  for (;__VERIFIER_nondet_int() != 3;) {", // 4
				"    n++;",    // 5
				"  }",         // 6
				"  return n;", // 7
				"}",           // 8
			),
			w:            &witness.Witness{Branchings: branches(4, 3, "true", "true", "true", "false")},
			wantInjected: 1,
			wantExit:     3,
		},
		{
			name: "do while",
			src: lines(
				"int __VERIFIER_nondet_int(void) { return 0; }", // 1
				"int main(void) {",                     // 2
				"  int n = 0;",                         // 3
				"  do {",                               // 4
				"    n++;",                             // 5
				"    if (n > 50) { return 99; }",       // 6
				"  } while (__VERIFIER_nondet_int());", // 7
				"  return n;",                          // 8
				"}",                                    // 9
			),
			w:            &witness.Witness{Branchings: branches(4, 3, "true", "true", "true", "false")},
			wantInjected: 1,
			wantExit:     4,
		},
		{
			name: "switch with constant",
			src: lines(
				"int __VERIFIER_nondet_int(void) { return 0; }", // 1
				"int main(void) {",                     // 2
				"  switch (__VERIFIER_nondet_int()) {", // 3
				"  case 7: return 70;",                 // 4
				"  case -3: return 30;",                // 5
				"  default: return 1;",                 // 6
				"  }",                                  // 7
				"}",                                    // 8
			),
			w:            &witness.Witness{Branchings: branches(3, 3, "7")},
			wantInjected: 1,
			wantExit:     70,
		},
		{
			name: "switch with negative constant",
			src: lines(
				"int __VERIFIER_nondet_int(void) { return 0; }", // 1
				"int main(void) {",                     // 2
				"  switch (__VERIFIER_nondet_int()) {", // 3
				"  case 7: return 70;",                 // 4
				"  case -3: return 30;",                // 5
				"  default: return 1;",                 // 6
				"  }",                                  // 7
				"}",                                    // 8
			),
			w:            &witness.Witness{Branchings: branches(3, 0, "-3")},
			wantInjected: 1,
			wantExit:     30,
		},
		{
			name: "switch with default is not matched",
			src: lines(
				"int __VERIFIER_nondet_int(void) { return 7; }", // 1
				"int main(void) {",                     // 2
				"  switch (__VERIFIER_nondet_int()) {", // 3
				"  case 7: return 70;",                 // 4
				"  default: return 1;",                 // 5
				"  }",                                  // 6
				"}",                                    // 7
			),
			w:            &witness.Witness{Branchings: branches(3, 3, "default")},
			wantInjected: 0,
			wantNote:     "waypoint value default does not determine an input value",
			wantExit:     70,
		},
		{
			name: "conditional operator, first operand",
			src: lines(
				"int __VERIFIER_nondet_int(void) { return 0; }", // 1
				"int main(void) {", // 2
				"  int x;",         // 3
				"  x = __VERIFIER_nondet_int() ? 10 : 20;", // 4
				"  return x;", // 5
				"}",           // 6
			),
			w:            &witness.Witness{Branchings: branches(4, 31, "true")},
			wantInjected: 1,
			wantExit:     10,
		},
		{
			name: "conditional operator, second operand",
			src: lines(
				"int __VERIFIER_nondet_int(void) { return 5; }", // 1
				"int main(void) {", // 2
				"  int x = (__VERIFIER_nondet_int() == 5) ? 10 : 20;", // 3
				"  return x;", // 4
				"}",           // 5
			),
			w:            &witness.Witness{Branchings: branches(3, 0, "false")},
			wantInjected: 1,
			wantExit:     20,
		},
		{
			name: "mirrored comparison",
			src: lines(
				"int __VERIFIER_nondet_int(void) { return 0; }", // 1
				"int main(void) {",                     // 2
				"  if (0 < __VERIFIER_nondet_int()) {", // 3
				"    return 11;",                       // 4
				"  }",                                  // 5
				"  return 22;",                         // 6
				"}",                                    // 7
			),
			w:            &witness.Witness{Branchings: branches(3, 3, "true")},
			wantInjected: 1,
			wantExit:     11,
		},
		{
			name: "mirrored comparison, not taken",
			src: lines(
				"int __VERIFIER_nondet_int(void) { return 5; }", // 1
				"int main(void) {",                     // 2
				"  if (0 < __VERIFIER_nondet_int()) {", // 3
				"    return 11;",                       // 4
				"  }",                                  // 5
				"  return 22;",                         // 6
				"}",                                    // 7
			),
			w:            &witness.Witness{Branchings: branches(3, 3, "false")},
			wantInjected: 1,
			wantExit:     22,
		},
		{
			name: "needed value is unrepresentable in the unsigned type",
			src: lines(
				"unsigned int __VERIFIER_nondet_uint(void) { return 0; }", // 1
				"int main(void) {",                      // 2
				"  if (__VERIFIER_nondet_uint() < 0) {", // 3
				"    return 11;",                        // 4
				"  }",                                   // 5
				"  return 22;",                          // 6
				"}",                                     // 7
			),
			w:            &witness.Witness{Branchings: branches(3, 3, "true")},
			wantInjected: 0,
			wantNote:     `no value of nondet type "uint" makes the comparison < 0 true`,
			wantExit:     22,
		},
		{
			name: "condition with && is not matched",
			src: lines(
				"int __VERIFIER_nondet_int(void) { return 0; }", // 1
				"int main(void) {", // 2
				"  if (__VERIFIER_nondet_int() && __VERIFIER_nondet_int() > 3) {", // 3
				"    return 11;", // 4
				"  }",            // 5
				"  return 22;",   // 6
				"}",              // 7
			),
			w:            &witness.Witness{Branchings: branches(3, 3, "true")},
			wantInjected: 0,
			wantNote:     "contains && or ||",
			wantExit:     22,
		},
		{
			name: "function_return wins over branching for the same site",
			src: lines(
				"int __VERIFIER_nondet_int(void) { return 0; }", // 1
				"int main(void) {",                     // 2
				"  switch (__VERIFIER_nondet_int()) {", // 3
				"  case 2: return 20;",                 // 4
				"  case 3: return 30;",                 // 5
				"  default: return 1;",                 // 6
				"  }",                                  // 7
				"}",                                    // 8
			),
			w: &witness.Witness{
				Points:     functionReturn(3, 33, "2"),
				Branchings: branches(3, 3, "3"),
			},
			wantInjected: 1,
			wantNote:     "not used: the nondet call site at 3:33 has values from function_return waypoints",
			wantExit:     20,
		},
		{
			name: "values at the limits of long long compile without warnings",
			src: lines(
				"long long __VERIFIER_nondet_longlong(void) { return 0; }",           // 1
				"unsigned long long __VERIFIER_nondet_ulonglong(void) { return 0; }", // 2
				"int main(void) {",  // 3
				"  int result = 0;", // 4
				"  if (__VERIFIER_nondet_longlong() >= -9223372036854775807) {", // 5
				"    result += 1;", // 6
				"  }",              // 7
				"  if (__VERIFIER_nondet_ulonglong() > 9223372036854775807) {", // 8
				"    result += 2;", // 9
				"  }",              // 10
				"  if (__VERIFIER_nondet_ulonglong() == 18446744073709551614ULL) {", // 11
				"    result += 4;", // 12
				"  }",              // 13
				"  if (__VERIFIER_nondet_longlong() < 2147483648) {", // 14
				"    result += 8;", // 15
				"  }",              // 16
				"  return result;", // 17
				"}",                // 18
			),
			w: &witness.Witness{Branchings: append(append(branches(5, 3, "false"), branches(8, 3, "true")...),
				append(branches(11, 3, "true"), branches(14, 3, "false")...)...)},
			gccArgs:      []string{"-Wall", "-Wextra", "-Werror"},
			wantInjected: 3,
			wantNote:     "branching at 11:3 (if, 1 waypoint) not matched: " + reasonUnsupportedCondition,
			wantExit:     2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := mustInstrument(t, tt.src, tt.w, Options{})
			if res.InjectedSites != tt.wantInjected {
				t.Errorf("InjectedSites = %d, want %d", res.InjectedSites, tt.wantInjected)
			}
			switch {
			case tt.wantNote == "" && len(res.Notes) != 0:
				t.Errorf("unexpected notes: %q", res.Notes)
			case tt.wantNote != "" && (len(res.Notes) != 1 || !strings.Contains(res.Notes[0], tt.wantNote)):
				t.Errorf("notes = %q, want one note containing %q", res.Notes, tt.wantNote)
			}
			code, stderr := compileAndRun(t, res.Source, tt.gccArgs...)
			if code != tt.wantExit {
				t.Errorf("exit code %d, want %d\nstderr: %s\nsource:\n%s", code, tt.wantExit, stderr, res.Source)
			}
			if !strings.Contains(stderr, tt.wantStderr) {
				t.Errorf("stderr %q should contain %q", stderr, tt.wantStderr)
			}
		})
	}
}

// All three kinds of waypoints in one program, with the reach_error wrapper.
func TestCompiledMixedStrategies(t *testing.T) {
	src := lines(
		"extern void reach_error(void);",                            // 1
		"int __VERIFIER_nondet_int(void) { return 0; }",             // 2
		"unsigned char __VERIFIER_nondet_uchar(void) { return 0; }", // 3
		"# 1 \"some/header.h\" 1",                                   // 4
		"int main(void) {",                                          // 5
		"  int a = __VERIFIER_nondet_int();",                        // 6
		"  unsigned char b;",                                        // 7
		"  b = __VERIFIER_nondet_uchar();",                          // 8
		"  // b is read",                                            // 9
		"  if (a != 1000 || b != 200) { return 1; }",                // 10
		"  int n = 0;",                                              // 11
		"  while (__VERIFIER_nondet_int() >= 5) {",                  // 12
		"    n++;",           // 13
		"  }",                // 14
		"  if (n == 3) {",    // 15
		"    reach_error();", // 16
		"  }",                // 17
		"  return 2;",        // 18
		"}",                  // 19
	)
	w := &witness.Witness{
		Points:      []witness.InjectionPoint{{Loc: witness.Location{Line: 6, Column: 33}, Value: "1000"}},
		Assumptions: []witness.Assumption{{Loc: witness.Location{Line: 10, Column: 3}, Variable: "b", Value: "200"}},
		Branchings:  []witness.Branching{branch(12, 3, "true"), branch(12, 3, "true"), branch(12, 3, "true"), branch(12, 3, "false")},
		Targets:     []witness.Location{{Line: 16, Column: 5}},
	}
	res := mustInstrument(t, src, w, Options{RewriteReachError: true})
	if res.InjectedSites != 3 || res.NondetSites != 3 || len(res.Notes) != 0 {
		t.Errorf("InjectedSites = %d, NondetSites = %d, Notes = %q", res.InjectedSites, res.NondetSites, res.Notes)
	}
	code, stderr := compileAndRun(t, res.Source, "-Wall", "-Werror")
	if code != 213 || stderr != "witness2test-match: reach_error called at line 16\n" {
		t.Errorf("exit code %d, stderr %q\nsource:\n%s", code, stderr, res.Source)
	}
}

// The range of long depends on the data model: the value that makes
// "long > 2147483647" true exists for LP64 only.
func TestCompiledBranchingDependsOnDataModel(t *testing.T) {
	src := lines(
		"long __VERIFIER_nondet_long(void) { return 0; }", // 1
		"int main(void) {", // 2
		"  if (__VERIFIER_nondet_long() > 2147483647) {", // 3
		"    return 11;", // 4
		"  }",            // 5
		"  if (__VERIFIER_nondet_long() >= 2147483647) {", // 6
		"    return 22;", // 7
		"  }",            // 8
		"  return 33;",   // 9
		"}",              // 10
	)
	w := &witness.Witness{Branchings: []witness.Branching{branch(3, 3, "true"), branch(6, 3, "true")}}
	t.Run("LP64", func(t *testing.T) {
		probe := exec.Command("gcc", "-x", "c", "-", "-fsyntax-only")
		probe.Stdin = strings.NewReader("_Static_assert(sizeof(long) == 8, \"LP64\");\n")
		if _, err := exec.LookPath("gcc"); err != nil || probe.Run() != nil {
			t.Skip("gcc does not build LP64 programs by default")
		}
		res := mustInstrument(t, src, w, Options{Model: "LP64"})
		if res.InjectedSites != 2 || len(res.Notes) != 0 {
			t.Errorf("InjectedSites = %d, Notes = %q", res.InjectedSites, res.Notes)
		}
		if code, _ := compileAndRun(t, res.Source, "-Wall", "-Werror"); code != 11 {
			t.Errorf("exit code %d, want 11", code)
		}
	})
	t.Run("ILP32", func(t *testing.T) {
		require32Bit(t)
		res := mustInstrument(t, src, w, Options{Model: "ILP32"})
		if res.InjectedSites != 1 || len(res.Notes) != 1 || !strings.Contains(res.Notes[0], `no value of nondet type "long"`) {
			t.Errorf("InjectedSites = %d, Notes = %q", res.InjectedSites, res.Notes)
		}
		if code, _ := compileAndRun(t, res.Source, "-m32", "-Wall", "-Werror"); code != 22 {
			t.Errorf("exit code %d, want 22", code)
		}
	})
}
