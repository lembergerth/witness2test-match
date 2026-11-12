// This file is part of witness2test-match,
// a tool to turn SV-COMP violation witnesses (format v2) into executable tests.
// https://github.com/lembergerth/witness2test-match
//
// SPDX-FileCopyrightText: 2026 Thomas Lemberger <https://thomaslemberger.com>
//
// SPDX-License-Identifier: Apache-2.0

package instrument

import (
	"strings"
	"testing"

	"witness2test/witness"
)

// assume is the assumption "x == value" at the given location.
func assume(line, column int, value string) witness.Assumption {
	return witness.Assumption{Loc: witness.Location{Line: line, Column: column}, Variable: "x", Value: value}
}

// checkInjection verifies the outcome of an instrumentation in which at most
// one call site is expected to receive values. wantValues are the injected
// values, "" if no site may be instrumented. wantNotes are substrings of the
// expected notes, in order.
func checkInjection(t *testing.T, src string, res Result, wantValues string, wantNotes []string) {
	t.Helper()
	if wantValues == "" {
		if res.InjectedSites != 0 {
			t.Errorf("InjectedSites = %d, want 0", res.InjectedSites)
		}
		if res.Source != src {
			t.Errorf("program must be unchanged.\ngot:\n%s", res.Source)
		}
	} else {
		if res.InjectedSites != 1 {
			t.Errorf("InjectedSites = %d, want 1", res.InjectedSites)
		}
		if want := "values[] = { " + wantValues + " };"; !strings.Contains(res.Source, want) {
			t.Errorf("Source should contain %q.\ngot:\n%s", want, res.Source)
		}
	}
	if len(res.Notes) != len(wantNotes) {
		t.Fatalf("got %d notes %q, want %d notes containing %q", len(res.Notes), res.Notes, len(wantNotes), wantNotes)
	}
	for i, want := range wantNotes {
		if !strings.Contains(res.Notes[i], want) {
			t.Errorf("note %d = %q, want it to contain %q", i, res.Notes[i], want)
		}
	}
}

const (
	notPlainAssignment = "previous statement is not a plain assignment from a nondet call"
	notAfterStatement  = "the assignment does not directly follow a line ending in ';', '{' or '}'"
	notStatementStart  = "location is not the first character of a statement"
	labelledStatement  = "statement at the location is labelled"
)

func TestAssumptionMatched(t *testing.T) {
	tests := []struct {
		name        string
		src         string
		assumptions []witness.Assumption
		wantValues  string
		wantCall    string // the rewritten call, "" to skip the check
	}{
		{
			name: "assignment on the previous line",
			src: lines(
				"int main() {",
				"  int x;",
				"  x = __VERIFIER_nondet_int();",
				"  if (x == 5) { return 1; }",
				"}"),
			assumptions: []witness.Assumption{assume(4, 3, "5")},
			wantValues:  "5",
			wantCall:    "  x = __VERIFIER_nondet_value_injection_3_29();",
		},
		{
			name: "declaration with initializer",
			src: lines(
				"int main() {",
				"  int x = __VERIFIER_nondet_int();",
				"  if (x == 5) { return 1; }",
				"}"),
			assumptions: []witness.Assumption{assume(3, 3, "-5")},
			wantValues:  "-5",
			wantCall:    "  int x = __VERIFIER_nondet_value_injection_2_33();",
		},
		{
			name: "type of several words",
			src: lines(
				"int main() {",
				"  const unsigned  long\tlong x = __VERIFIER_nondet_ulonglong();",
				"  return x;",
				"}"),
			assumptions: []witness.Assumption{assume(3, 3, "7ULL")},
			wantValues:  "7ULL",
		},
		{
			name: "typedef name as type",
			src: lines(
				"int main() {",
				"  my_int_t x = __VERIFIER_nondet_int();",
				"  return x;",
				"}"),
			assumptions: []witness.Assumption{assume(3, 3, "7")},
			wantValues:  "7",
		},
		{
			name: "void parameter list and free whitespace",
			src: lines(
				"int main() {",
				"\tx\t=  __VERIFIER_nondet_int ( void )  ;  ",
				"\treturn x;",
				"}"),
			assumptions: []witness.Assumption{assume(3, 2, "7")},
			wantValues:  "7",
		},
		{
			name: "no whitespace at all",
			src: lines(
				"int main() {",
				"x=__VERIFIER_nondet_int();",
				"return x;",
				"}"),
			assumptions: []witness.Assumption{assume(3, 1, "7")},
			wantValues:  "7",
		},
		{
			name: "blank and comment-only lines in between",
			src: lines(
				"int main() {",
				"  foo(); // done",
				"",
				"  // about to read",
				"  /* really */",
				"  x = __VERIFIER_nondet_int();",
				"  ",
				"  // x is now set",
				"\t/* x == 5 */  ",
				"",
				"  return x;",
				"}"),
			assumptions: []witness.Assumption{assume(11, 3, "5")},
			wantValues:  "5",
		},
		{
			name: "unspecified column means the first non-whitespace column",
			src: lines(
				"int main() {",
				"  x = __VERIFIER_nondet_int();",
				"    return x;",
				"}"),
			assumptions: []witness.Assumption{assume(3, 0, "5")},
			wantValues:  "5",
		},
		{
			name: "assignment and next statement on the same line",
			src: lines(
				"int main() {",
				"  int x = __VERIFIER_nondet_int(); if (x == 5) { return 1; }",
				"}"),
			assumptions: []witness.Assumption{assume(2, 36, "5")},
			wantValues:  "5",
			wantCall:    "  int x = __VERIFIER_nondet_value_injection_2_33(); if (x == 5) { return 1; }",
		},
		{
			name: "previous line ends a block",
			src: lines(
				"int main() {",
				"  if (c) { foo(); }",
				"  x = __VERIFIER_nondet_int();",
				"  return x;",
				"}"),
			assumptions: []witness.Assumption{assume(4, 3, "5")},
			wantValues:  "5",
		},
		{
			name: "previous line ends in a statement with trailing line comment",
			src: lines(
				"int main() {",
				"  foo(); // if (c)",
				"  x = __VERIFIER_nondet_int();",
				"  return x;",
				"}"),
			assumptions: []witness.Assumption{assume(4, 3, "5")},
			wantValues:  "5",
		},
		{
			name: "previous line contains a string that looks like a comment",
			src: lines(
				"int main() {",
				"  puts(\"http://example.org\");",
				"  x = __VERIFIER_nondet_int();",
				"  return x;",
				"}"),
			assumptions: []witness.Assumption{assume(4, 3, "5")},
			wantValues:  "5",
		},
		{
			name: "assignment is the first statement of a block",
			src: lines(
				"int main() {",
				"  while (c) {",
				"    x = __VERIFIER_nondet_int();",
				"    foo(x);",
				"  }",
				"}"),
			assumptions: []witness.Assumption{assume(4, 5, "5")},
			wantValues:  "5",
		},
		{
			name: "several assumptions are queued in document order",
			src: lines(
				"int main() {",
				"  while (c) {",
				"    x = __VERIFIER_nondet_int();",
				"    foo(x);",
				"  }",
				"}"),
			assumptions: []witness.Assumption{assume(4, 5, "3"), assume(4, 0, "1"), assume(4, 5, "2")},
			wantValues:  "3, 1, 2",
		},
		{
			name: "next statement starts with an identifier that is no label",
			src: lines(
				"int main() {",
				"  x = __VERIFIER_nondet_int();",
				"  default_value = x ? a : b;",
				"}"),
			assumptions: []witness.Assumption{assume(3, 3, "5")},
			wantValues:  "5",
		},
		{
			name: "next statement starts with a conditional expression",
			src: lines(
				"int main() {",
				"  x = __VERIFIER_nondet_int();",
				"  x ? foo() : bar();",
				"}"),
			assumptions: []witness.Assumption{assume(3, 3, "5")},
			wantValues:  "5",
		},
		{
			name: "values of other types",
			src: lines(
				"int main() {",
				"  double x = __VERIFIER_nondet_double();",
				"  return x > 1;",
				"}"),
			assumptions: []witness.Assumption{assume(3, 3, "1.5e3")},
			wantValues:  "1.5e3",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := mustInstrument(t, tt.src, &witness.Witness{Assumptions: tt.assumptions}, Options{})
			checkInjection(t, tt.src, res, tt.wantValues, nil)
			if tt.wantCall != "" && !strings.Contains(res.Source, "\n"+tt.wantCall+"\n") {
				t.Errorf("Source should contain the line %q.\ngot:\n%s", tt.wantCall, res.Source)
			}
		})
	}
}

func TestAssumptionNotMatched(t *testing.T) {
	// %s is replaced by the line(s) under test; the assumption is located at
	// the statement "return x;" unless stated otherwise.
	tests := []struct {
		name       string
		src        string
		assumption witness.Assumption
		wantNote   string
	}{
		// Rule (a): the location.
		{
			name:       "line beyond the end of the program",
			src:        lines("int main() {", "  x = __VERIFIER_nondet_int();", "  return x;", "}"),
			assumption: assume(40, 3, "5"),
			wantNote:   "assumption at 40:3 (x == 5) not matched: line 40 does not exist",
		},
		{
			name:       "column beyond the end of the line",
			src:        lines("int main() {", "  x = __VERIFIER_nondet_int();", "  return x;", "}"),
			assumption: assume(3, 12, "5"),
			wantNote:   "assumption at 3:12 (x == 5) not matched: " + notStatementStart,
		},
		{
			name:       "column at whitespace",
			src:        lines("int main() {", "  x = __VERIFIER_nondet_int();", "  return x;", "}"),
			assumption: assume(3, 2, "5"),
			wantNote:   notStatementStart,
		},
		{
			name:       "column inside a comment",
			src:        lines("int main() {", "  x = __VERIFIER_nondet_int();", "  /* c */ return x;", "}"),
			assumption: assume(3, 3, "5"),
			wantNote:   notStatementStart,
		},
		{
			name:       "blank line with unspecified column",
			src:        lines("int main() {", "  x = __VERIFIER_nondet_int();", "  ", "  return x;", "}"),
			assumption: assume(3, 0, "5"),
			wantNote:   "assumption at 3 (x == 5) not matched: " + notStatementStart,
		},
		{
			name:       "other statement before the location on the same line",
			src:        lines("int main() {", "  x = __VERIFIER_nondet_int();", "  foo(); return x;", "}"),
			assumption: assume(3, 10, "5"),
			wantNote:   notPlainAssignment,
		},
		{
			name:       "comment before the location on the same line",
			src:        lines("int main() {", "  x = __VERIFIER_nondet_int();", "  /* c */ return x;", "}"),
			assumption: assume(3, 11, "5"),
			wantNote:   notPlainAssignment,
		},
		{
			name:       "location in the middle of a statement",
			src:        lines("int main() {", "  x = __VERIFIER_nondet_int();", "  return x;", "}"),
			assumption: assume(3, 10, "5"),
			wantNote:   notPlainAssignment,
		},
		{
			name:       "assignment and more before the location on the same line",
			src:        lines("int main() {", "  { x = __VERIFIER_nondet_int(); return x; }", "}"),
			assumption: assume(2, 34, "5"),
			wantNote:   notPlainAssignment,
		},
		{
			name:       "no line before the location",
			src:        lines("return x;"),
			assumption: assume(1, 1, "5"),
			wantNote:   notPlainAssignment,
		},
		{
			name:       "multi-line comment between assignment and location",
			src:        lines("int main() {", "  x = __VERIFIER_nondet_int();", "  /* a", "     b */", "  return x;", "}"),
			assumption: assume(5, 3, "5"),
			wantNote:   notPlainAssignment,
		},
		{
			name:       "line with two comments between assignment and location",
			src:        lines("int main() {", "  x = __VERIFIER_nondet_int();", "  /* a */ /* b */", "  return x;", "}"),
			assumption: assume(4, 3, "5"),
			wantNote:   notPlainAssignment,
		},
		{
			name:       "preprocessor directive between assignment and location",
			src:        lines("int main() {", "  x = __VERIFIER_nondet_int();", "#endif", "  return x;", "}"),
			assumption: assume(4, 3, "5"),
			wantNote:   notPlainAssignment,
		},
		// Rule (b): the assignment.
		{
			name:       "assignment of a constant",
			src:        lines("int main() {", "  x = 5;", "  return x;", "}"),
			assumption: assume(3, 3, "5"),
			wantNote:   notPlainAssignment,
		},
		{
			name:       "assignment of another function",
			src:        lines("int main() {", "  x = my__VERIFIER_nondet_int();", "  return x;", "}"),
			assumption: assume(3, 3, "5"),
			wantNote:   notPlainAssignment,
		},
		{
			name:       "cast",
			src:        lines("int main() {", "  x = (int) __VERIFIER_nondet_int();", "  return x;", "}"),
			assumption: assume(3, 3, "5"),
			wantNote:   notPlainAssignment,
		},
		{
			name:       "parenthesized call",
			src:        lines("int main() {", "  x = (__VERIFIER_nondet_int());", "  return x;", "}"),
			assumption: assume(3, 3, "5"),
			wantNote:   notPlainAssignment,
		},
		{
			name:       "arithmetic",
			src:        lines("int main() {", "  x = __VERIFIER_nondet_int() + 1;", "  return x;", "}"),
			assumption: assume(3, 3, "5"),
			wantNote:   notPlainAssignment,
		},
		{
			name:       "negation",
			src:        lines("int main() {", "  x = -__VERIFIER_nondet_int();", "  return x;", "}"),
			assumption: assume(3, 3, "5"),
			wantNote:   notPlainAssignment,
		},
		{
			name:       "compound assignment",
			src:        lines("int main() {", "  x += __VERIFIER_nondet_int();", "  return x;", "}"),
			assumption: assume(3, 3, "5"),
			wantNote:   notPlainAssignment,
		},
		{
			name:       "comparison instead of assignment",
			src:        lines("int main() {", "  x == __VERIFIER_nondet_int();", "  return x;", "}"),
			assumption: assume(3, 3, "5"),
			wantNote:   notPlainAssignment,
		},
		{
			name:       "second declarator after the call",
			src:        lines("int main() {", "  int x = __VERIFIER_nondet_int(), y;", "  return x;", "}"),
			assumption: assume(3, 3, "5"),
			wantNote:   notPlainAssignment,
		},
		{
			name:       "second declarator before the variable",
			src:        lines("int main() {", "  int y, x = __VERIFIER_nondet_int();", "  return x;", "}"),
			assumption: assume(3, 3, "5"),
			wantNote:   notPlainAssignment,
		},
		{
			name:       "chained assignment",
			src:        lines("int main() {", "  y = x = __VERIFIER_nondet_int();", "  return x;", "}"),
			assumption: assume(3, 3, "5"),
			wantNote:   notPlainAssignment,
		},
		{
			name:       "pointer declaration",
			src:        lines("int main() {", "  char *x = __VERIFIER_nondet_pointer();", "  return x;", "}"),
			assumption: assume(3, 3, "0"),
			wantNote:   notPlainAssignment,
		},
		{
			name:       "dereferenced pointer",
			src:        lines("int main() {", "  *x = __VERIFIER_nondet_int();", "  return x;", "}"),
			assumption: assume(3, 3, "5"),
			wantNote:   notPlainAssignment,
		},
		{
			name:       "array element",
			src:        lines("int main() {", "  x[0] = __VERIFIER_nondet_int();", "  return x;", "}"),
			assumption: assume(3, 3, "5"),
			wantNote:   notPlainAssignment,
		},
		{
			name:       "array declaration",
			src:        lines("int main() {", "  int a[2], x = __VERIFIER_nondet_int();", "  return x;", "}"),
			assumption: assume(3, 3, "5"),
			wantNote:   notPlainAssignment,
		},
		{
			name:       "struct member",
			src:        lines("int main() {", "  s.x = __VERIFIER_nondet_int();", "  return x;", "}"),
			assumption: assume(3, 3, "5"),
			wantNote:   notPlainAssignment,
		},
		{
			name:       "call with argument",
			src:        lines("int main() {", "  x = __VERIFIER_nondet_int(1);", "  return x;", "}"),
			assumption: assume(3, 3, "5"),
			wantNote:   notPlainAssignment,
		},
		{
			name:       "missing semicolon",
			src:        lines("int main() {", "  x = __VERIFIER_nondet_int()", "  ; return x;", "}"),
			assumption: assume(3, 5, "5"),
			wantNote:   notPlainAssignment,
		},
		{
			name:       "two statements on the assignment line",
			src:        lines("int main() {", "  foo(); x = __VERIFIER_nondet_int();", "  return x;", "}"),
			assumption: assume(3, 3, "5"),
			wantNote:   notPlainAssignment,
		},
		{
			name:       "statement after the assignment on its line",
			src:        lines("int main() {", "  x = __VERIFIER_nondet_int(); x++;", "  return x;", "}"),
			assumption: assume(3, 3, "5"),
			wantNote:   notPlainAssignment,
		},
		{
			name:       "closing brace after the assignment on its line",
			src:        lines("int main() {", "  if (c) {", "  x = __VERIFIER_nondet_int(); }", "  return x;", "}"),
			assumption: assume(4, 3, "5"),
			wantNote:   notPlainAssignment,
		},
		{
			name:       "opening brace before the assignment on its line",
			src:        lines("int main() {", "  { x = __VERIFIER_nondet_int();", "  return x; }", "}"),
			assumption: assume(3, 3, "5"),
			wantNote:   notPlainAssignment,
		},
		{
			name:       "line comment after the assignment",
			src:        lines("int main() {", "  x = __VERIFIER_nondet_int(); // read x", "  return x;", "}"),
			assumption: assume(3, 3, "5"),
			wantNote:   notPlainAssignment,
		},
		{
			name:       "block comment after the assignment",
			src:        lines("int main() {", "  x = __VERIFIER_nondet_int(); /* read x */", "  return x;", "}"),
			assumption: assume(3, 3, "5"),
			wantNote:   notPlainAssignment,
		},
		{
			name:       "assignment is the body of an else on the same line",
			src:        lines("int main() {", "  if (c) { foo(); }", "  else x = __VERIFIER_nondet_int();", "  return x;", "}"),
			assumption: assume(4, 3, "5"),
			wantNote:   notPlainAssignment,
		},
		{
			name:       "assignment is the body of a do on the same line",
			src:        lines("int main() {", "  foo();", "  do x = __VERIFIER_nondet_int();", "  while (x);", "}"),
			assumption: assume(4, 3, "5"),
			wantNote:   notPlainAssignment,
		},
		{
			name:       "assignment is returned",
			src:        lines("int main() {", "  foo();", "  return x = __VERIFIER_nondet_int();", "  return x;", "}"),
			assumption: assume(4, 3, "5"),
			wantNote:   notPlainAssignment,
		},
		{
			name:       "assignment after a case label on the same line",
			src:        lines("int main() {", "  switch (c) {", "  case 1: x = __VERIFIER_nondet_int();", "  return x; }", "}"),
			assumption: assume(4, 3, "5"),
			wantNote:   notPlainAssignment,
		},
		{
			name:       "assignment inside a continued line comment",
			src:        lines("int main() {", "  foo(); // \\", "  x = __VERIFIER_nondet_int();", "  return x;", "}"),
			assumption: assume(4, 3, "5"),
			wantNote:   notPlainAssignment,
		},
		{
			name:       "assignment inside a comment on the line of the location",
			src:        lines("int main() {", "  foo();", "  /* x = __VERIFIER_nondet_int(); */ return x;", "}"),
			assumption: assume(3, 38, "5"),
			wantNote:   notPlainAssignment,
		},
		{
			name:       "assignment to another variable",
			src:        lines("int main() {", "  y = __VERIFIER_nondet_int();", "  return x;", "}"),
			assumption: assume(3, 3, "5"),
			wantNote:   "assumption at 3:3 (x == 5) not matched: previous statement assigns to y, not to x",
		},
		{
			name:       "declaration of another variable",
			src:        lines("int main() {", "  int x2 = __VERIFIER_nondet_int();", "  return x;", "}"),
			assumption: assume(3, 3, "5"),
			wantNote:   "previous statement assigns to x2, not to x",
		},
		// Rule (c): the line before the assignment.
		{
			name:       "assignment is the body of an if",
			src:        lines("int main() {", "  if (c)", "    x = __VERIFIER_nondet_int();", "  return x;", "}"),
			assumption: assume(4, 3, "5"),
			wantNote:   "assumption at 4:3 (x == 5) not matched: " + notAfterStatement,
		},
		{
			name:       "assignment is the body of an else",
			src:        lines("int main() {", "  if (c) { foo(); }", "  else", "    x = __VERIFIER_nondet_int();", "  return x;", "}"),
			assumption: assume(5, 3, "5"),
			wantNote:   notAfterStatement,
		},
		{
			name:       "assignment is the body of a for",
			src:        lines("int main() {", "  for (i = 0; i < 3; i++)", "    x = __VERIFIER_nondet_int();", "  return x;", "}"),
			assumption: assume(4, 3, "5"),
			wantNote:   notAfterStatement,
		},
		{
			name:       "assignment is the body of a while with comment lines in between",
			src:        lines("int main() {", "  while (c)", "", "    // body", "    x = __VERIFIER_nondet_int();", "  return x;", "}"),
			assumption: assume(6, 3, "5"),
			wantNote:   notAfterStatement,
		},
		{
			name:       "assignment is the body of a do",
			src:        lines("int main() {", "  do", "    x = __VERIFIER_nondet_int();", "  while (x);", "}"),
			assumption: assume(4, 3, "5"),
			wantNote:   notAfterStatement,
		},
		{
			name:       "assignment follows a label",
			src:        lines("int main() {", "  again:", "    x = __VERIFIER_nondet_int();", "  return x;", "}"),
			assumption: assume(4, 3, "5"),
			wantNote:   notAfterStatement,
		},
		{
			name:       "assignment follows a case label",
			src:        lines("int main() {", "  switch (c) {", "  case 1:", "    x = __VERIFIER_nondet_int();", "  return x; }", "}"),
			assumption: assume(5, 3, "5"),
			wantNote:   notAfterStatement,
		},
		{
			name:       "assignment continues an expression",
			src:        lines("int main() {", "  y = z +", "  x = __VERIFIER_nondet_int();", "  return x;", "}"),
			assumption: assume(4, 3, "5"),
			wantNote:   notAfterStatement,
		},
		{
			name:       "braceless if with a line comment that ends in a semicolon",
			src:        lines("int main() {", "  if (c) // foo();", "    x = __VERIFIER_nondet_int();", "  return x;", "}"),
			assumption: assume(4, 3, "5"),
			wantNote:   notAfterStatement,
		},
		{
			name:       "braceless if with a string that looks like a comment",
			src:        lines("int main() {", "  if (strcmp(s, \";//\") == 0)", "    x = __VERIFIER_nondet_int();", "  return x;", "}"),
			assumption: assume(4, 3, "5"),
			wantNote:   notAfterStatement,
		},
		{
			name:       "previous line ends in a block comment",
			src:        lines("int main() {", "  foo(); /* c */", "  x = __VERIFIER_nondet_int();", "  return x;", "}"),
			assumption: assume(4, 3, "5"),
			wantNote:   notAfterStatement,
		},
		{
			name:       "previous line is a preprocessor directive",
			src:        lines("int main() {", "  if (c)", "#define FOO foo();", "  x = __VERIFIER_nondet_int();", "  return x;", "}"),
			assumption: assume(5, 3, "5"),
			wantNote:   notAfterStatement,
		},
		{
			name:       "previous line is a continued macro definition",
			src:        lines("#define READ() \\", "  foo(); \\", "  x = __VERIFIER_nondet_int();", "int y;"),
			assumption: assume(4, 1, "5"),
			wantNote:   notAfterStatement,
		},
		{
			name:       "no line before the assignment",
			src:        lines("x = __VERIFIER_nondet_int();", "return x;"),
			assumption: assume(2, 1, "5"),
			wantNote:   notAfterStatement,
		},
		{
			name:       "assignment on the line of the location is the body of an if",
			src:        lines("int main() {", "  if (c)", "    x = __VERIFIER_nondet_int(); return x;", "}"),
			assumption: assume(3, 34, "5"),
			wantNote:   notAfterStatement,
		},
		// Rule (d): labels.
		{
			name:       "labelled statement",
			src:        lines("int main() {", "  x = __VERIFIER_nondet_int();", "  again: return x;", "}"),
			assumption: assume(3, 3, "5"),
			wantNote:   "assumption at 3:3 (x == 5) not matched: " + labelledStatement,
		},
		{
			name:       "label with whitespace before the colon",
			src:        lines("int main() {", "  x = __VERIFIER_nondet_int();", "  again  :", "  return x;", "}"),
			assumption: assume(3, 3, "5"),
			wantNote:   labelledStatement,
		},
		{
			name:       "label with comment before the colon",
			src:        lines("int main() {", "  x = __VERIFIER_nondet_int();", "  again /* c */ : return x;", "}"),
			assumption: assume(3, 3, "5"),
			wantNote:   labelledStatement,
		},
		{
			name:       "case label",
			src:        lines("int main() {", "  switch (c) {", "  x = __VERIFIER_nondet_int();", "  case 1: return x; }", "}"),
			assumption: assume(4, 3, "5"),
			wantNote:   labelledStatement,
		},
		{
			name:       "case label with parenthesis",
			src:        lines("int main() {", "  switch (c) {", "  x = __VERIFIER_nondet_int();", "  case(1): return x; }", "}"),
			assumption: assume(4, 3, "5"),
			wantNote:   labelledStatement,
		},
		{
			name:       "default label",
			src:        lines("int main() {", "  switch (c) {", "  x = __VERIFIER_nondet_int();", "  default: return x; }", "}"),
			assumption: assume(4, 0, "5"),
			wantNote:   "assumption at 4 (x == 5) not matched: " + labelledStatement,
		},
		{
			name:       "default label with whitespace",
			src:        lines("int main() {", "  switch (c) {", "  x = __VERIFIER_nondet_int();", "  default : return x; }", "}"),
			assumption: assume(4, 3, "5"),
			wantNote:   labelledStatement,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := mustInstrument(t, tt.src, &witness.Witness{Assumptions: []witness.Assumption{tt.assumption}}, Options{})
			checkInjection(t, tt.src, res, "", []string{tt.wantNote})
		})
	}
}

// Rule (e): the call of the assignment must be a call site known to
// CollectNondetCalls.
func TestAssumptionRequiresKnownCallSite(t *testing.T) {
	src := lines("int main() {", "  x = __VERIFIER_nondet_int();", "  return x;", "}")
	a := assume(3, 3, "5")

	m := newMatcher(src, CollectNondetCalls(src), modelLP64)
	site, reason := m.matchAssumption(a)
	if reason != "" || site.Line != 2 || site.ColumnOfClosingParen != 29 {
		t.Fatalf("matchAssumption = %+v, %q; want the site at 2:29", site, reason)
	}

	m = newMatcher(src, nil, modelLP64)
	if _, reason := m.matchAssumption(a); reason != "the nondet call of the assignment is not a recognized call site" {
		t.Errorf("reason = %q", reason)
	}
}

func TestAssumptionNotes(t *testing.T) {
	src := lines(
		"int main() {",                       // 1
		"  int x = __VERIFIER_nondet_int();", // 2
		"  foo(x);",                          // 3
		"  x = 5;",                           // 4
		"  bar(x); baz(x);",                  // 5
		"  y = __VERIFIER_nondet_int();",     // 6
		"  return x;",                        // 7
		"}",                                  // 8
	)
	w := &witness.Witness{Assumptions: []witness.Assumption{
		assume(7, 3, "1"),
		assume(5, 11, "2"),
		assume(3, 3, "3"),
		{Loc: witness.Location{Line: 5, Column: 3}, Variable: "y", Value: "'a'"},
		assume(5, 3, "5"),
		assume(5, 0, "6"),
		assume(99, 0, "7"),
	}}
	res := mustInstrument(t, src, w, Options{})
	want := []string{
		"assumption at 5 (x == 6) not matched: " + notPlainAssignment,
		"assumption at 5:3 (y == 'a') not matched: " + notPlainAssignment,
		"assumption at 5:3 (x == 5) not matched: " + notPlainAssignment,
		"assumption at 5:11 (x == 2) not matched: " + notPlainAssignment,
		"assumption at 7:3 (x == 1) not matched: previous statement assigns to y, not to x",
		"assumption at 99 (x == 7) not matched: line 99 does not exist",
	}
	if strings.Join(res.Notes, "\n") != strings.Join(want, "\n") {
		t.Errorf("notes:\n%s\nwant:\n%s", strings.Join(res.Notes, "\n"), strings.Join(want, "\n"))
	}
	if res.InjectedSites != 1 || !strings.Contains(res.Source, "values[] = { 3 };") {
		t.Errorf("the matched assumption must still be used (InjectedSites = %d):\n%s", res.InjectedSites, res.Source)
	}
}

func TestFunctionReturnWinsOverAssumption(t *testing.T) {
	src := lines(
		"int main() {",
		"  int x = __VERIFIER_nondet_int();",
		"  int y = __VERIFIER_nondet_int();",
		"  return x + y;",
		"}",
	)
	w := &witness.Witness{
		Points: []witness.InjectionPoint{{Loc: witness.Location{Line: 2, Column: 33}, Value: "10"}},
		Assumptions: []witness.Assumption{
			assume(3, 3, "20"),
			{Loc: witness.Location{Line: 4, Column: 3}, Variable: "y", Value: "30"},
			assume(3, 3, "21"),
		},
	}
	res := mustInstrument(t, src, w, Options{})
	if res.InjectedSites != 2 || res.NondetSites != 2 {
		t.Errorf("InjectedSites = %d, NondetSites = %d, want 2 and 2", res.InjectedSites, res.NondetSites)
	}
	for _, want := range []string{
		"int __VERIFIER_nondet_value_injection_2_33(void) {\n  static const int values[] = { 10 };",
		"int __VERIFIER_nondet_value_injection_3_33(void) {\n  static const int values[] = { 30 };",
	} {
		if !strings.Contains(res.Source, want) {
			t.Errorf("Source should contain %q.\ngot:\n%s", want, res.Source)
		}
	}
	wantNotes := []string{
		"assumption at 3:3 (x == 20) not used: the nondet call site at 2:33 has values from function_return waypoints",
		"assumption at 3:3 (x == 21) not used: the nondet call site at 2:33 has values from function_return waypoints",
	}
	if strings.Join(res.Notes, "\n") != strings.Join(wantNotes, "\n") {
		t.Errorf("notes:\n%s\nwant:\n%s", strings.Join(res.Notes, "\n"), strings.Join(wantNotes, "\n"))
	}
}

func TestCommentOnlyLine(t *testing.T) {
	tests := []struct {
		name string
		src  string
		line int
		want bool
	}{
		{"line comment", "a;\n  // c\nb;", 2, true},
		{"line comment without indentation", "a;\n// c\nb;", 2, true},
		{"block comment", "a;\n  /* c */  \nb;", 2, true},
		{"empty block comment", "a;\n/**/\nb;", 2, true},
		{"block comment containing a line comment", "a;\n/* // */\nb;", 2, true},
		{"line comment containing a block comment", "a;\n// /* c */ x;\nb;", 2, true},
		{"code", "a;\nx;\nb;", 2, false},
		{"blank", "a;\n\nb;", 2, false},
		{"code after block comment", "a;\n/* c */ x;\nb;", 2, false},
		{"code before line comment", "a;\nx; // c\nb;", 2, false},
		{"two block comments", "a;\n/* c */ /* d */\nb;", 2, false},
		{"adjacent block comments", "a;\n/* c *//* d */\nb;", 2, false},
		{"start of a multi-line comment", "a;\n/* c\nd */\nb;", 2, false},
		{"end of a multi-line comment", "a;\n/* c\nd */\nb;", 3, false},
		{"inside a multi-line comment", "a; /*\n// c\n*/\nb;", 2, false},
		{"block comment inside a multi-line comment", "a; /*\n/* c */\nb;", 2, false},
		{"continuation of a line comment", "a; // c \\\n// d\nb;", 2, false},
		{"division", "a;\n/ 2;\nb;", 2, false},
		{"string that looks like a comment", "a;\n\"// c\"\nb;", 2, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := newSourceText(tt.src).isCommentOnlyLine(tt.line); got != tt.want {
				t.Errorf("isCommentOnlyLine(%d) of %q = %v, want %v", tt.line, tt.src, got, tt.want)
			}
		})
	}
}

func TestCompiledAssumption(t *testing.T) {
	t.Run("drives the program into a branch", func(t *testing.T) {
		src := lines(
			"extern int __VERIFIER_nondet_int(void);", // 1
			"extern void reach_error(void);",          // 2
			"int main(void) {",                        // 3
			"  int x;",                                // 4
			"  x = __VERIFIER_nondet_int();",          // 5
			"  if (x == 1234) {",                      // 6
			"    reach_error();",                      // 7
			"  }",                                     // 8
			"  return 3;",                             // 9
			"}",                                       // 10
		)
		if code, _ := compileAndRun(t, src); code != 214 {
			t.Fatalf("without witness: exit code %d, want 214 (no witness value)", code)
		}
		w := &witness.Witness{Assumptions: []witness.Assumption{assume(6, 3, "1234")}}
		res := mustInstrument(t, src, w, Options{RewriteReachError: true})
		checkInjection(t, src, res, "1234", nil)
		code, stderr := compileAndRun(t, res.Source)
		if code != 213 || stderr != "witness2test-match: reach_error called at line 7\n" {
			t.Errorf("exit code %d, stderr %q", code, stderr)
		}
	})
	t.Run("one value per call, then the witness is inconsistent", func(t *testing.T) {
		src := lines(
			"extern unsigned char __VERIFIER_nondet_uchar(void);", // 1
			"int main(void) {",                                 // 2
			"  int sum = 0;",                                   // 3
			"  for (int i = 0; i < LIMIT; i++) {",              // 4
			"    unsigned char x = __VERIFIER_nondet_uchar();", // 5
			"    sum += x;",                                    // 6
			"  }",                                              // 7
			"  return sum;",                                    // 8
			"}",                                                // 9
		)
		w := &witness.Witness{Assumptions: []witness.Assumption{assume(6, 5, "1"), assume(6, 5, "20"), assume(6, 0, "0x30")}}
		res := mustInstrument(t, src, w, Options{})
		checkInjection(t, src, res, "1, 20, 0x30", nil)
		if code, _ := compileAndRun(t, res.Source, "-DLIMIT=3"); code != 1+20+0x30 {
			t.Errorf("exit code %d, want %d", code, 1+20+0x30)
		}
		code, stderr := compileAndRun(t, res.Source, "-DLIMIT=4")
		if code != 214 || !strings.Contains(stderr, "nondet overflow at 5:47") {
			t.Errorf("exit code %d, stderr %q; want 214 and an overflow message", code, stderr)
		}
	})
}

func TestEndsStatementOrBlock(t *testing.T) {
	tests := []struct {
		name string
		src  string
		line int
		want bool
	}{
		{"semicolon", "foo();", 1, true},
		{"opening brace", "if (c) {", 1, true},
		{"closing brace", "}", 1, true},
		{"trailing whitespace", "foo();  \t\r", 1, true},
		{"trailing line comment", "foo(); // if (c)", 1, true},
		{"trailing line comment without space", "foo();//c", 1, true},
		{"string that looks like a comment", "puts(\"http://example.org\");", 1, true},
		{"character literals that look like a comment", "c = '/'; d = '/';", 1, true},
		{"parenthesis", "if (c)", 1, false},
		{"else", "} else", 1, false},
		{"colon", "label:", 1, false},
		{"operator", "x = y +", 1, false},
		{"backslash", "foo(); \\", 1, false},
		{"trailing block comment", "foo(); /* c */", 1, false},
		{"semicolon only in the line comment", "if (c) // foo();", 1, false},
		{"semicolon only in a string", "if (strcmp(s, \";//\") == 0)", 1, false},
		{"semicolon in an unterminated string", "s = \"abc;", 1, false},
		{"semicolon in an unterminated block comment", "if (c) /* foo();", 1, false},
		{"line inside a block comment", "if (c) /* a\n  b;\n*/", 2, false},
		{"continuation of a line comment", "if (c) // a \\\n  b;", 2, false},
		{"preprocessor directive", "#define FOO foo();", 1, false},
		{"indented preprocessor directive", "  # define FOO {", 1, false},
		{"preprocessor directive after comment", "/* c */ #define FOO }", 1, false},
		{"comment only", "// foo();", 1, false},
		{"blank", "   ", 1, false},
		{"later line", "if (c)\nfoo();\nbar()", 2, true},
		{"last line without semicolon", "if (c)\nfoo();\nbar()", 3, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := newSourceText(tt.src).endsStatementOrBlock(tt.line); got != tt.want {
				t.Errorf("endsStatementOrBlock(%d) of %q = %v, want %v", tt.line, tt.src, got, tt.want)
			}
		})
	}
}

func TestStartsWithLabel(t *testing.T) {
	tests := []struct {
		statement string
		want      bool
	}{
		{"again: x++;", true},
		{"again : x++;", true},
		{"again\t:", true},
		{"_l1:x++;", true},
		{"case 1: x++;", true},
		{"case(1): x++;", true},
		{"case", true},
		{"default: x++;", true},
		{"default :", true},
		{"x++;", false},
		{"x ? a : b;", false},
		{"x = y ? a : b;", false},
		{"ns::f();", false},
		{"ns ::f();", false},
		{"cases: x++;", true},
		{"cases = 1;", false},
		{"default_value = 1;", false},
		{"caseless(1);", false},
		{"1: x++;", false},
		{": x++;", false},
		{"return x;", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := startsWithLabel(tt.statement); got != tt.want {
			t.Errorf("startsWithLabel(%q) = %v, want %v", tt.statement, got, tt.want)
		}
	}
}
