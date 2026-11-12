// This file is part of witness2test-match,
// a tool to turn SV-COMP violation witnesses (format v2) into executable tests.
// https://github.com/lembergerth/witness2test-match
//
// SPDX-FileCopyrightText: 2026 Thomas Lemberger <https://thomaslemberger.com>
//
// SPDX-License-Identifier: Apache-2.0

package instrument

import (
	"reflect"
	"strings"
	"testing"

	"witness2test/witness"
)

func TestNeutraliseLineDirectives(t *testing.T) {
	tests := []struct {
		name string
		line string
		want string
	}{
		{"linemarker", `# 100 "foo.h"`, ""},
		{"linemarker with flags", `# 1 "/usr/include/stdio.h" 1 3 4`, ""},
		{"linemarker without file", `# 7`, ""},
		{"linemarker without space", `#7 "a.c"`, ""},
		{"line directive", `#line 5`, ""},
		{"line directive with file", `#line 5 "a.c"`, ""},
		{"indented with inner whitespace", "  \t#  line \t 12   \"x y.c\"  ", ""},
		{"trailing carriage return", "# 3 \"a.c\"\r", ""},
		{"empty file name", `# 3 ""`, ""},
		{"define", `#define X 1`, `#define X 1`},
		{"include", `#include "a.h"`, `#include "a.h"`},
		{"pragma", `#pragma pack(1)`, `#pragma pack(1)`},
		{"line directive without number", `#line`, `#line`},
		{"line directive with macro", `#line LINE`, `#line LINE`},
		{"line glued to number", `#line5`, `#line5`},
		{"other directive starting with line", `#linefoo 3`, `#linefoo 3`},
		{"text after the number", `# 5 foo`, `# 5 foo`},
		{"unterminated file name", `# 5 "foo`, `# 5 "foo`},
		{"code before the hash", `x; # 5`, `x; # 5`},
		{"code after the marker", `# 5 "a.c" int x;`, `# 5 "a.c" int x;`},
		{"plain code", `  x = 5;`, `  x = 5;`},
		{"number only", `5`, `5`},
		{"empty line", ``, ``},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Surrounding lines must be left alone and the line count kept.
			in := "int a;\n" + tt.line + "\nint b;\n"
			want := "int a;\n" + tt.want + "\nint b;\n"
			if got := neutraliseLineDirectives(in); got != want {
				t.Errorf("neutraliseLineDirectives(%q) = %q, want %q", in, got, want)
			}
		})
	}
}

func TestNeutraliseLineDirectivesKeepsLineCount(t *testing.T) {
	in := "# 1 \"a.c\"\n# 1 \"<built-in>\"\nint x;\n#line 99\nint y;"
	got := neutraliseLineDirectives(in)
	if got != "\n\nint x;\n\nint y;" {
		t.Errorf("got %q", got)
	}
	if strings.Count(got, "\n") != strings.Count(in, "\n") {
		t.Errorf("line count changed: %q", got)
	}
}

func TestInstrumentWitnessFunctionReturn(t *testing.T) {
	src := "int main() {\n  int x = __VERIFIER_nondet_int();\n  int y = __VERIFIER_nondet_int();\n  return x + y;\n}\n"
	w := &witness.Witness{Points: []witness.InjectionPoint{
		{Loc: witness.Location{Line: 2, Column: 33}, Value: "42"},
		{Loc: witness.Location{Line: 2, Column: 33}, Value: "43"},
	}}
	res, err := InstrumentWitness(src, w, Options{})
	if err != nil {
		t.Fatalf("InstrumentWitness: %v", err)
	}
	if res.NondetSites != 2 || res.InjectedSites != 1 {
		t.Errorf("NondetSites = %d, InjectedSites = %d, want 2 and 1", res.NondetSites, res.InjectedSites)
	}
	if len(res.Notes) != 0 {
		t.Errorf("unexpected notes: %q", res.Notes)
	}
	wantProgram := "#line 1\nint main() {\n  int x = __VERIFIER_nondet_value_injection_2_33();\n  int y = __VERIFIER_nondet_int();\n  return x + y;\n}\n"
	if !strings.HasSuffix(res.Source, wantProgram) {
		t.Errorf("Source should end with the program after '#line 1'.\ngot:\n%s", res.Source)
	}
	if !strings.HasPrefix(res.Source, "/* witness2test-match: generated definitions */\n") {
		t.Errorf("Source should start with the generated definitions.\ngot:\n%s", res.Source)
	}
	if !strings.Contains(res.Source, "static const int values[] = { 42, 43 };") {
		t.Errorf("values must be injected in document order.\ngot:\n%s", res.Source)
	}
	if !strings.Contains(res.Source, "_Exit(214);") {
		t.Error("exhausting the values must exit with exitcodes.WitnessInconsistent")
	}
}

// A function_return waypoint may sit on a call of any function. One that is
// not on a nondet call provides no input value; it is reported, not an error.
func TestInstrumentWitnessUnmatchedFunctionReturnIsNoted(t *testing.T) {
	src := "int main() {\n  int x = __VERIFIER_nondet_int();\n  return x;\n}\n"
	tests := []struct {
		name string
		loc  witness.Location
		note string
	}{
		{"line without call", witness.Location{Line: 3, Column: 10}, "function_return at 3:10 (1 value) not matched: no __VERIFIER_nondet_X() call ends at the location"},
		{"line beyond the program", witness.Location{Line: 99, Column: 5}, "function_return at 99:5 (1 value) not matched: no __VERIFIER_nondet_X() call ends at the location"},
		{"column of the opening parenthesis", witness.Location{Line: 2, Column: 32}, "function_return at 2:32 (1 value) not matched: no __VERIFIER_nondet_X() call ends at the location"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := &witness.Witness{Points: []witness.InjectionPoint{{Loc: tt.loc, Value: "1"}}}
			res, err := InstrumentWitness(src, w, Options{})
			if err != nil {
				t.Fatalf("InstrumentWitness: %v", err)
			}
			if res.InjectedSites != 0 || res.Source != src {
				t.Errorf("nothing may be instrumented (InjectedSites = %d):\n%s", res.InjectedSites, res.Source)
			}
			if len(res.Notes) != 1 || res.Notes[0] != tt.note {
				t.Errorf("notes = %q, want %q", res.Notes, tt.note)
			}
		})
	}
}

func TestInstrumentWitnessUsesMatchedFunctionReturnsBesideUnmatched(t *testing.T) {
	src := "int f(void);\nint main() {\n  int x = __VERIFIER_nondet_int();\n  int y = f();\n  return x + y;\n}\n"
	w := &witness.Witness{Points: []witness.InjectionPoint{
		{Loc: witness.Location{Line: 4, Column: 13}, Value: "7"},
		{Loc: witness.Location{Line: 3, Column: 33}, Value: "5"},
		{Loc: witness.Location{Line: 4, Column: 13}, Value: "8"},
	}}
	res, err := InstrumentWitness(src, w, Options{})
	if err != nil {
		t.Fatalf("InstrumentWitness: %v", err)
	}
	if res.InjectedSites != 1 || !strings.Contains(res.Source, "values[] = { 5 };") {
		t.Errorf("the nondet call must get its value (InjectedSites = %d):\n%s", res.InjectedSites, res.Source)
	}
	want := "function_return at 4:13 (2 values) not matched: no __VERIFIER_nondet_X() call ends at the location"
	if len(res.Notes) != 1 || res.Notes[0] != want {
		t.Errorf("notes = %q, want %q", res.Notes, want)
	}
}

func TestInstrumentWitnessWithoutInjection(t *testing.T) {
	tests := []struct {
		name string
		src  string
		w    *witness.Witness
		want string
	}{
		{
			name: "program without directives is unchanged",
			src:  "int main() {\n  int x = __VERIFIER_nondet_int();\n  reach_error();\n}\n",
			w:    &witness.Witness{},
			want: "int main() {\n  int x = __VERIFIER_nondet_int();\n  reach_error();\n}\n",
		},
		{
			name: "nil witness",
			src:  "int main() { return 0; }\n",
			w:    nil,
			want: "int main() { return 0; }\n",
		},
		{
			name: "linemarkers are neutralised",
			src:  "# 1 \"a.c\"\nint main() {\n# 100 \"foo.h\" 2\n  return 0;\n#line 7 \"a.c\"\n}\n",
			w:    &witness.Witness{},
			want: "\nint main() {\n\n  return 0;\n\n}\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := InstrumentWitness(tt.src, tt.w, Options{})
			if err != nil {
				t.Fatalf("InstrumentWitness: %v", err)
			}
			if res.Source != tt.want {
				t.Errorf("Source = %q, want %q", res.Source, tt.want)
			}
			if res.InjectedSites != 0 {
				t.Errorf("InjectedSites = %d, want 0", res.InjectedSites)
			}
		})
	}
}

func TestInstrumentWitnessReachError(t *testing.T) {
	src := "void reach_error(){}\n# 5 \"a.c\"\nint main(){\n  if (0) reach_error();\n  reach_error(); reach_error ( );\n}\n"
	t.Run("rewritten with __LINE__ behind a #line 1", func(t *testing.T) {
		res, err := InstrumentWitness(src, &witness.Witness{}, Options{RewriteReachError: true})
		if err != nil {
			t.Fatalf("InstrumentWitness: %v", err)
		}
		wantProgram := "#line 1\nvoid reach_error(){}\n\nint main(){\n  if (0) __VERIFIER_w2t_reach_error(__LINE__);\n  __VERIFIER_w2t_reach_error(__LINE__); __VERIFIER_w2t_reach_error(__LINE__);\n}\n"
		if !strings.HasSuffix(res.Source, wantProgram) {
			t.Errorf("unexpected program part.\ngot:\n%s", res.Source)
		}
		defs := strings.TrimSuffix(res.Source, wantProgram)
		for _, want := range []string{
			"void __VERIFIER_w2t_reach_error(int line)",
			"witness2test-match: reach_error called at line ",
			"syscall(__W2T_SYS_WRITE, 2, ",
			"_Exit(213);",
		} {
			if !strings.Contains(defs, want) {
				t.Errorf("definitions should contain %q.\ngot:\n%s", want, defs)
			}
		}
		for _, unwanted := range []string{"printf", "stdio", "#include"} {
			if strings.Contains(defs, unwanted) {
				t.Errorf("definitions must not use %q.\ngot:\n%s", unwanted, defs)
			}
		}
	})
	t.Run("left untouched", func(t *testing.T) {
		res, err := InstrumentWitness(src, &witness.Witness{}, Options{RewriteReachError: false})
		if err != nil {
			t.Fatalf("InstrumentWitness: %v", err)
		}
		want := "void reach_error(){}\n\nint main(){\n  if (0) reach_error();\n  reach_error(); reach_error ( );\n}\n"
		if res.Source != want {
			t.Errorf("Source = %q, want %q", res.Source, want)
		}
	})
	t.Run("no wrapper without call site", func(t *testing.T) {
		res, err := InstrumentWitness("int main() { return 0; }\n", &witness.Witness{}, Options{RewriteReachError: true})
		if err != nil {
			t.Fatalf("InstrumentWitness: %v", err)
		}
		if res.Source != "int main() { return 0; }\n" {
			t.Errorf("Source = %q", res.Source)
		}
	})
	t.Run("no wrapper when only values are injected", func(t *testing.T) {
		src := "int main() {\n  int x = __VERIFIER_nondet_int();\n  if (x) reach_error();\n}\n"
		w := &witness.Witness{Points: []witness.InjectionPoint{{Loc: witness.Location{Line: 2, Column: 33}, Value: "1"}}}
		res, err := InstrumentWitness(src, w, Options{RewriteReachError: false})
		if err != nil {
			t.Fatalf("InstrumentWitness: %v", err)
		}
		if strings.Contains(res.Source, "__VERIFIER_w2t_reach_error") {
			t.Errorf("no wrapper expected.\ngot:\n%s", res.Source)
		}
		if !strings.Contains(res.Source, "  if (x) reach_error();\n") {
			t.Errorf("reach_error() call must be left untouched.\ngot:\n%s", res.Source)
		}
	})
}

func TestInstrumentWitnessModel(t *testing.T) {
	tests := []struct {
		model   string
		wantErr bool
	}{
		{"", false},
		{"LP64", false},
		{"ILP32", false},
		{"LLP64", true},
		{"ilp32", true},
	}
	for _, tt := range tests {
		t.Run(tt.model, func(t *testing.T) {
			_, err := InstrumentWitness("int main() { return 0; }\n", &witness.Witness{}, Options{Model: tt.model})
			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && !strings.Contains(err.Error(), "data model") {
				t.Errorf("error should name the data model: %v", err)
			}
		})
	}
}

func TestInstrumentWitnessDoesNotModifyWitness(t *testing.T) {
	src := "int main() {\n  int x = __VERIFIER_nondet_int();\n  return x;\n}\n"
	w := &witness.Witness{Points: []witness.InjectionPoint{{Loc: witness.Location{Line: 2, Column: 33}, Value: "1"}}}
	before := *w
	if _, err := InstrumentWitness(src, w, Options{}); err != nil {
		t.Fatalf("InstrumentWitness: %v", err)
	}
	if !reflect.DeepEqual(before, *w) {
		t.Errorf("witness was modified: %+v", w)
	}
}

// The generated definitions are ordered by the location of the call site,
// whatever kind of waypoint the values come from.
func TestInstrumentWitnessOrdersDefinitionsByLocation(t *testing.T) {
	src := "int main() {\n" +
		"  if (__VERIFIER_nondet_int()) { return 1; }\n" +
		"  int x = __VERIFIER_nondet_int();\n" +
		"  int y = __VERIFIER_nondet_int(); int z = __VERIFIER_nondet_int();\n" +
		"  return x + y + z;\n" +
		"}\n"
	w := &witness.Witness{
		Points: []witness.InjectionPoint{
			{Loc: witness.Location{Line: 4, Column: 66}, Value: "4"},
			{Loc: witness.Location{Line: 4, Column: 33}, Value: "3"},
		},
		Assumptions: []witness.Assumption{{Loc: witness.Location{Line: 4, Column: 3}, Variable: "x", Value: "2"}},
		Branchings:  []witness.Branching{{Loc: witness.Location{Line: 2, Column: 3}, Value: "true"}},
	}
	res, err := InstrumentWitness(src, w, Options{})
	if err != nil {
		t.Fatalf("InstrumentWitness: %v", err)
	}
	if res.InjectedSites != 4 || res.NondetSites != 4 || len(res.Notes) != 0 {
		t.Fatalf("InjectedSites = %d, NondetSites = %d, Notes = %q", res.InjectedSites, res.NondetSites, res.Notes)
	}
	last := -1
	for _, name := range []string{
		"__VERIFIER_nondet_value_injection_2_29(void)",
		"__VERIFIER_nondet_value_injection_3_33(void)",
		"__VERIFIER_nondet_value_injection_4_33(void)",
		"__VERIFIER_nondet_value_injection_4_66(void)",
	} {
		pos := strings.Index(res.Source, name)
		if pos < 0 {
			t.Fatalf("definition of %s is missing.\ngot:\n%s", name, res.Source)
		}
		if pos < last {
			t.Errorf("definition of %s is out of order.\ngot:\n%s", name, res.Source)
		}
		last = pos
	}
}

// A witness is untrusted input: whatever location a waypoint names, the
// instrumentation must neither fail nor match anything by accident.
func TestInstrumentWitnessSurvivesArbitraryLocations(t *testing.T) {
	src := "#include <stdio.h>\n" +
		"# 3 \"a.c\"\n" +
		"/* if (x) ? \n" +
		"   x = __VERIFIER_nondet_int(); */\n" +
		"int f(int x) { return (x) ? 1 : 2; }\n" +
		"int main() {\n" +
		"\tint x;\n" +
		"  x = __VERIFIER_nondet_int(); // read\n" +
		"  do x++; while (x < 3);\n" +
		"  do {\n" +
		"  for (;;) { if (x) ? 1 : 2; }\n" +
		"  char *s = \"if (\\\"?\"; char c = '?';\n" +
		"  while (\n" +
		"  switch (x\n" +
		"  ? ) (\n" +
		"  }\n" +
		"  return x;\r\n" +
		"}\n" +
		"do { \n" +
		"?"
	lineCount := strings.Count(src, "\n") + 1
	for line := -1; line <= lineCount+1; line++ {
		for column := -2; column <= 45; column++ {
			loc := witness.Location{Line: line, Column: column}
			w := &witness.Witness{
				Assumptions: []witness.Assumption{{Loc: loc, Variable: "x", Value: "1"}},
				Branchings:  []witness.Branching{{Loc: loc, Value: "true"}, {Loc: loc, Value: "7"}},
			}
			res, err := InstrumentWitness(src, w, Options{RewriteReachError: true})
			if err != nil {
				t.Fatalf("location %d:%d: %v", line, column, err)
			}
			if res.InjectedSites != 0 {
				t.Errorf("location %d:%d: unexpected injection.\nnotes: %q", line, column, res.Notes)
			}
			// One note for the assumption, and one per branching waypoint or
			// one for the construct both of them refer to; none for a
			// construct whose condition has no nondet call.
			if len(res.Notes) < 1 || len(res.Notes) > 3 {
				t.Errorf("location %d:%d: got %d notes, want 1 to 3: %q", line, column, len(res.Notes), res.Notes)
			}
		}
	}
}

func TestInstrumentWitnessWithCarriageReturns(t *testing.T) {
	src := "int main() {\r\n" +
		"  int x = __VERIFIER_nondet_int();\r\n" +
		"  // comment\r\n" +
		"\r\n" +
		"  while (__VERIFIER_nondet_int() > 2) {\r\n" +
		"    x++;\r\n" +
		"  }\r\n" +
		"  return x;\r\n" +
		"}\r\n"
	w := &witness.Witness{
		Assumptions: []witness.Assumption{{Loc: witness.Location{Line: 5, Column: 3}, Variable: "x", Value: "9"}},
		Branchings:  []witness.Branching{{Loc: witness.Location{Line: 5}, Value: "true"}, {Loc: witness.Location{Line: 5, Column: 3}, Value: "false"}},
	}
	res, err := InstrumentWitness(src, w, Options{})
	if err != nil {
		t.Fatalf("InstrumentWitness: %v", err)
	}
	if res.InjectedSites != 2 || len(res.Notes) != 0 {
		t.Errorf("InjectedSites = %d, Notes = %q", res.InjectedSites, res.Notes)
	}
	for _, want := range []string{"values[] = { 9 };", "values[] = { 3, 2 };"} {
		if !strings.Contains(res.Source, want) {
			t.Errorf("Source should contain %q.\ngot:\n%s", want, res.Source)
		}
	}
}

// A branching waypoint on a condition without any nondet call says nothing
// about input values; it must not produce a note. Witnesses consist mostly of
// such waypoints.
func TestNoNoteForBranchingWithoutNondetCall(t *testing.T) {
	program := "extern int __VERIFIER_nondet_int(void);\n" +
		"int main() {\n" +
		"  int x = 1;\n" +
		"  if (x > 0) { x = 2; }\n" +
		"  while (x < 5) { x++; }\n" +
		"  if (x && __VERIFIER_nondet_int()) { return 1; }\n" +
		"  return 0;\n" +
		"}\n"
	w := &witness.Witness{Branchings: []witness.Branching{
		{Loc: witness.Location{Line: 4, Column: 3}, Value: "true"},
		{Loc: witness.Location{Line: 5, Column: 3}, Value: "true"},
		{Loc: witness.Location{Line: 6, Column: 3}, Value: "true"},
	}}
	result, err := InstrumentWitness(program, w, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Notes) != 1 || !strings.HasPrefix(result.Notes[0], "branching at 6:3 (if, 1 waypoint) not matched: ") {
		t.Errorf("notes = %q, want exactly one note for the condition at 6:3", result.Notes)
	}
}
