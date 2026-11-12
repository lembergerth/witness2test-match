// This file is part of witness2test-match,
// a tool to turn SV-COMP violation witnesses (format v2) into executable tests.
// https://github.com/lembergerth/witness2test-match
//
// SPDX-FileCopyrightText: 2026 Thomas Lemberger <https://thomaslemberger.com>
//
// SPDX-License-Identifier: Apache-2.0

package instrument

import (
	"math/big"
	"strings"
	"testing"

	"witness2test/witness"
)

// branch is a branching waypoint with the given value.
func branch(line, column int, value string) witness.Branching {
	return witness.Branching{Loc: witness.Location{Line: line, Column: column}, Value: value}
}

func TestFindConstruct(t *testing.T) {
	tests := []struct {
		name       string
		src        string
		line, col  int
		wantKind   string
		wantExpr   string // text of the controlling expression
		wantReason string // not matched if set
	}{
		// if, while, switch
		{name: "if", src: "  if (x > 0) {", line: 1, col: 3, wantKind: "if", wantExpr: "x > 0"},
		{name: "if without whitespace", src: "if(x){", line: 1, col: 1, wantKind: "if", wantExpr: "x"},
		{name: "if with nested parentheses", src: "  if \t ( f(a, (b)) ) {", line: 1, col: 3, wantKind: "if", wantExpr: " f(a, (b)) "},
		{name: "else if", src: "  } else if (y) {", line: 1, col: 10, wantKind: "if", wantExpr: "y"},
		{name: "while", src: "  while (i < n)", line: 1, col: 3, wantKind: "while", wantExpr: "i < n"},
		{name: "switch", src: "  switch (k) {", line: 1, col: 3, wantKind: "switch", wantExpr: "k"},
		{name: "on a later line", src: "int main() {\n  foo();\n  if (a) {\n", line: 3, col: 3, wantKind: "if", wantExpr: "a"},
		{name: "parentheses in literals and comments", src: `  if (c == ')' || s == "(" /* ( */) {`, line: 1, col: 3, wantKind: "if", wantExpr: `c == ')' || s == "(" /* ( */`},
		// unspecified column
		{name: "column 0: first keyword", src: "  } else if (y) {", line: 1, col: 0, wantKind: "if", wantExpr: "y"},
		{name: "column 0: first of several keywords", src: "  while (a) if (b) x++;", line: 1, col: 0, wantKind: "while", wantExpr: "a"},
		{name: "column 0: keyword wins over earlier '?'", src: "  x = (a) ? 1 : 2; if (b) x++;", line: 1, col: 0, wantKind: "if", wantExpr: "b"},
		{name: "column 0: '?' without keyword", src: "  x = (a) ? 1 : (b) ? 2 : 3;", line: 1, col: 0, wantKind: "?", wantExpr: "(a)"},
		{name: "column 0: keyword in string and comment is skipped", src: `  puts("if (x)"); /* while (y) */ switch (z) {`, line: 1, col: 0, wantKind: "switch", wantExpr: "z"},
		{name: "column 0: identifiers containing keywords are skipped", src: "  iffy(a); redo(b); do_it(c); while (d) x++;", line: 1, col: 0, wantKind: "while", wantExpr: "d"},
		{name: "column 0: do", src: "  do {\n  x++;\n  } while (x < 3);", line: 1, col: 0, wantKind: "do", wantExpr: "x < 3"},
		{name: "column 0: nothing on the line", src: "  x = y + 1;", line: 1, col: 0, wantReason: "no if, while, for, switch, do or '?' on the line"},
		{name: "column 0: only in a comment", src: "  x = 1; // if (x)", line: 1, col: 0, wantReason: "no if, while, for, switch, do or '?' on the line"},
		// for
		{name: "for", src: "  for (i = 0; i < n; i++) {", line: 1, col: 3, wantKind: "for", wantExpr: " i < n"},
		{name: "for with empty clauses", src: "  for (;x;) {", line: 1, col: 3, wantKind: "for", wantExpr: "x"},
		{name: "for with empty condition", src: "  for (;;) {", line: 1, col: 3, wantKind: "for", wantExpr: ""},
		{name: "for with semicolon in nested parentheses", src: "  for (i = ({ a; b; }); f(i); i++) {", line: 1, col: 3, wantKind: "for", wantExpr: " f(i)"},
		{name: "for with semicolon in literals", src: `  for (c = ';'; s != ";"; c++) {`, line: 1, col: 3, wantKind: "for", wantExpr: ` s != ";"`},
		{name: "for with two clauses", src: "  for (a; b) {", line: 1, col: 3, wantReason: "the for statement does not have exactly three clauses"},
		{name: "for with four clauses", src: "  for (a; b; c; d) {", line: 1, col: 3, wantReason: "the for statement does not have exactly three clauses"},
		{name: "for over several lines", src: "  for (i = 0;\n i < n; i++) {", line: 1, col: 3, wantReason: "the controlling expression is not enclosed in parentheses on the line of the for"},
		// do
		{name: "do", src: "  do {\n    x++;\n  } while (x < 3);", line: 1, col: 3, wantKind: "do", wantExpr: "x < 3"},
		{name: "do on one line", src: "do { x++; } while(x);", line: 1, col: 1, wantKind: "do", wantExpr: "x"},
		{name: "do with brace and while on their own lines", src: "do\n{\n  x++;\n}\n\nwhile (x);", line: 1, col: 1, wantKind: "do", wantExpr: "x"},
		{name: "outer do of nested loops", src: "do { do { a; } while (b); if (d) { e; } } while (c);", line: 1, col: 1, wantKind: "do", wantExpr: "c"},
		{name: "inner do of nested loops", src: "do { do { a; } while (b); if (d) { e; } } while (c);", line: 1, col: 6, wantKind: "do", wantExpr: "b"},
		{name: "do with braces in literals and comments", src: "do { c = '}'; s = \"}\"; /* } */ // }\n } while (x);", line: 1, col: 1, wantKind: "do", wantExpr: "x"},
		{name: "do without braces", src: "do x++; while (x < 3);", line: 1, col: 1, wantReason: "the do statement is not of the form do { ... } while (...)"},
		{name: "do with unbalanced braces", src: "do { x++; while (x < 3);", line: 1, col: 1, wantReason: "the do statement is not of the form do { ... } while (...)"},
		{name: "do without while", src: "do { x++; } until (x < 3);", line: 1, col: 1, wantReason: "the do statement is not of the form do { ... } while (...)"},
		{name: "do with while as part of an identifier", src: "do { x++; } while_not (x < 3);", line: 1, col: 1, wantReason: "the do statement is not of the form do { ... } while (...)"},
		{name: "do with condition over several lines", src: "do { x++; } while (x <\n 3);", line: 1, col: 1, wantReason: "the do statement is not of the form do { ... } while (...)"},
		{name: "do with parenthesis on the next line", src: "do { x++; } while\n(x < 3);", line: 1, col: 1, wantReason: "the do statement is not of the form do { ... } while (...)"},
		// conditional operator
		{name: "? after parenthesized condition", src: "  x = (a > b) ? 1 : 2;", line: 1, col: 15, wantKind: "?", wantExpr: "(a > b)"},
		{name: "? directly after the parenthesis", src: "  x = (a > b)? 1 : 2;", line: 1, col: 14, wantKind: "?", wantExpr: "(a > b)"},
		{name: "? after nondet call", src: "  x = __VERIFIER_nondet_int() ? 1 : 2;", line: 1, col: 31, wantKind: "?", wantExpr: "__VERIFIER_nondet_int()"},
		{name: "? after nondet call with whitespace", src: "  x = __VERIFIER_nondet_int ( void ) ? 1 : 2;", line: 1, col: 38, wantKind: "?", wantExpr: "__VERIFIER_nondet_int ( void )"},
		{name: "? after return", src: "  return (a) ? 1 : 2;", line: 1, col: 14, wantKind: "?", wantExpr: "(a)"},
		{name: "? after return without whitespace", src: "  return(a) ? 1 : 2;", line: 1, col: 13, wantKind: "?", wantExpr: "(a)"},
		{name: "? after return of nondet call", src: "  return __VERIFIER_nondet_int() ? 1 : 2;", line: 1, col: 34, wantKind: "?", wantExpr: "__VERIFIER_nondet_int()"},
		{name: "? after compound assignment", src: "  x += (a) ? 1 : 2;", line: 1, col: 12, wantKind: "?", wantExpr: "(a)"},
		{name: "? as first argument", src: "  f((a) ? 1 : 2, (b) ? 3 : 4);", line: 1, col: 9, wantKind: "?", wantExpr: "(a)"},
		{name: "? as second argument", src: "  f((a) ? 1 : 2, (b) ? 3 : 4);", line: 1, col: 22, wantKind: "?", wantExpr: "(b)"},
		{name: "? after semicolon", src: "  x = 1; (a) ? f() : g();", line: 1, col: 14, wantKind: "?", wantExpr: "(a)"},
		{name: "? after opening brace", src: "  { (a) ? f() : g(); }", line: 1, col: 9, wantKind: "?", wantExpr: "(a)"},
		{name: "? after closing brace", src: "  { } (a) ? f() : g();", line: 1, col: 11, wantKind: "?", wantExpr: "(a)"},
		{name: "? nested in the second operand", src: "  x = (a) ? (b) ? 1 : 2 : 3;", line: 1, col: 17, wantKind: "?", wantExpr: "(b)"},
		{name: "? nested in the third operand", src: "  x = (a) ? 1 : (b) ? 2 : 3;", line: 1, col: 21, wantKind: "?", wantExpr: "(b)"},
		{name: "? after comment", src: "  x = /* c */ (a) /* d */ ? 1 : 2;", line: 1, col: 27, wantKind: "?", wantExpr: "(a)"},
		{name: "? after identifier", src: "  x = a ? 1 : 2;", line: 1, col: 9, wantReason: "the condition of '?' is not a parenthesized expression or a nondet call on the line of the '?'"},
		{name: "? after literal", src: "  x = 1 ? 1 : 2;", line: 1, col: 9, wantReason: "the condition of '?' is not a parenthesized expression or a nondet call on the line of the '?'"},
		{name: "? after array access", src: "  x = a[0] ? 1 : 2;", line: 1, col: 12, wantReason: "the condition of '?' is not a parenthesized expression or a nondet call on the line of the '?'"},
		{name: "? at the start of the line after whitespace", src: "  x = (a)\n    ? 1 : 2;", line: 2, col: 5, wantReason: "the condition of '?' is not a parenthesized expression or a nondet call on the line of the '?'"},
		{name: "? after parenthesis opened on a previous line", src: "  x = (a +\n    b) ? 1 : 2;", line: 2, col: 8, wantReason: "the condition of '?' is not a parenthesized expression or a nondet call on the line of the '?'"},
		{name: "? after call of another function", src: "  x = f(a) ? 1 : 2;", line: 1, col: 12, wantReason: "the condition of '?' is not a parenthesized expression or a nondet call on the line of the '?'"},
		{name: "? after sizeof", src: "  x = sizeof(a) ? 1 : 2;", line: 1, col: 17, wantReason: "the condition of '?' is not a parenthesized expression or a nondet call on the line of the '?'"},
		{name: "? after call of a nondet-like function", src: "  x = my__VERIFIER_nondet_int() ? 1 : 2;", line: 1, col: 33, wantReason: "the condition of '?' is not a parenthesized expression or a nondet call on the line of the '?'"},
		{name: "? after addition", src: "  x = y + (a) ? 1 : 2;", line: 1, col: 15, wantReason: "the condition of '?' may be part of a larger expression"},
		{name: "? after addition to nondet call", src: "  x = y + __VERIFIER_nondet_int() ? 1 : 2;", line: 1, col: 35, wantReason: "the condition of '?' may be part of a larger expression"},
		{name: "? after negation", src: "  x = !(a) ? 1 : 2;", line: 1, col: 12, wantReason: "the condition of '?' may be part of a larger expression"},
		{name: "? after negated nondet call", src: "  x = !__VERIFIER_nondet_int() ? 1 : 2;", line: 1, col: 32, wantReason: "the condition of '?' may be part of a larger expression"},
		{name: "? after cast", src: "  x = (int)(a) ? 1 : 2;", line: 1, col: 16, wantReason: "the condition of '?' may be part of a larger expression"},
		{name: "? after &&", src: "  x = y && (a) ? 1 : 2;", line: 1, col: 16, wantReason: "the condition of '?' may be part of a larger expression"},
		{name: "? after ==", src: "  x = y == (a) ? 1 : 2;", line: 1, col: 16, wantReason: "the condition of '?' may be part of a larger expression"},
		{name: "? after !=", src: "  x = y != (a) ? 1 : 2;", line: 1, col: 16, wantReason: "the condition of '?' may be part of a larger expression"},
		{name: "? after <=", src: "  x = y <= (a) ? 1 : 2;", line: 1, col: 16, wantReason: "the condition of '?' may be part of a larger expression"},
		{name: "? after >=", src: "  x = y >= (a) ? 1 : 2;", line: 1, col: 16, wantReason: "the condition of '?' may be part of a larger expression"},
		{name: "? after <", src: "  x = y < (a) ? 1 : 2;", line: 1, col: 15, wantReason: "the condition of '?' may be part of a larger expression"},
		{name: "? after sizeof of a nondet call", src: "  x = sizeof __VERIFIER_nondet_int() ? 1 : 2;", line: 1, col: 38, wantReason: "the condition of '?' may be part of a larger expression"},
		{name: "? after nondet call behind an identifier ending in return", src: "  x = noreturn __VERIFIER_nondet_int() ? 1 : 2;", line: 1, col: 40, wantReason: "the condition of '?' may be part of a larger expression"},
		// An operand that starts its line may continue the previous line.
		{name: "? after operand at the start of the line", src: "  (a) ? f() : g();", line: 1, col: 7, wantReason: "the condition of '?' may be part of a larger expression"},
		{name: "? after operand at the start of the text", src: "(a) ? f() : g();", line: 1, col: 5, wantReason: "the condition of '?' may be part of a larger expression"},
		{name: "? after nondet call at the start of the line", src: "__VERIFIER_nondet_int() ? f() : g();", line: 1, col: 25, wantReason: "the condition of '?' may be part of a larger expression"},
		{name: "? after nondet call that continues an addition of the previous line", src: "  x = a +\n    __VERIFIER_nondet_int() ? 1 : 2;", line: 2, col: 29, wantReason: "the condition of '?' may be part of a larger expression"},
		{name: "? after parenthesized operand that continues a comparison of the previous line", src: "  x = a <\n\t(b) ? 1 : 2;", line: 2, col: 6, wantReason: "the condition of '?' may be part of a larger expression"},
		{name: "? after operand that starts the line after an assignment", src: "  x =\n    (a) ? 1 : 2;", line: 2, col: 9, wantReason: "the condition of '?' may be part of a larger expression"},
		{name: "? after operand behind a comment at the start of the line", src: "  x = a + /* c\n */ (b) ? 1 : 2;", line: 2, col: 9, wantReason: "the condition of '?' may be part of a larger expression"},
		{name: "? after operand behind a token at the start of the line", src: "  f(a +\n    b, (c) ? 1 : 2);", line: 2, col: 12, wantKind: "?", wantExpr: "(c)"},
		{name: "? after another identifier", src: "  x = y z (a) ? 1 : 2;", line: 1, col: 15, wantReason: "the condition of '?' is not a parenthesized expression or a nondet call on the line of the '?'"},
		{name: "? after identifier ending in return", src: "  x = noreturn (a) ? 1 : 2;", line: 1, col: 20, wantReason: "the condition of '?' is not a parenthesized expression or a nondet call on the line of the '?'"},
		// the location
		{name: "line 0", src: "if (a) {", line: 0, col: 1, wantReason: "line 0 does not exist"},
		{name: "line beyond the program", src: "if (a) {", line: 2, col: 1, wantReason: "line 2 does not exist"},
		{name: "column beyond the line", src: "if (a) {", line: 1, col: 9, wantReason: "no if, while, for, switch, do or '?' at the location"},
		{name: "column at another token", src: "  if (a) {", line: 1, col: 6, wantReason: "no if, while, for, switch, do or '?' at the location"},
		{name: "column at whitespace before the keyword", src: "  if (a) {", line: 1, col: 2, wantReason: "no if, while, for, switch, do or '?' at the location"},
		{name: "column inside the keyword", src: "  while (a) {", line: 1, col: 4, wantReason: "no if, while, for, switch, do or '?' at the location"},
		{name: "keyword is the start of an identifier", src: "  iffy (a) {", line: 1, col: 3, wantReason: "no if, while, for, switch, do or '?' at the location"},
		{name: "keyword is the end of an identifier", src: "  endif (a) {", line: 1, col: 6, wantReason: "no if, while, for, switch, do or '?' at the location"},
		{name: "do is the start of double", src: "  double d;", line: 1, col: 3, wantReason: "no if, while, for, switch, do or '?' at the location"},
		{name: "keyword in a comment", src: "  /* if (a) */ x++;", line: 1, col: 6, wantReason: "no if, while, for, switch, do or '?' at the location"},
		{name: "keyword in a string", src: `  s = "if (a)";`, line: 1, col: 8, wantReason: "no if, while, for, switch, do or '?' at the location"},
		{name: "? in a character literal", src: "  c = (a) == '?' ? 1 : 2;", line: 1, col: 15, wantReason: "no if, while, for, switch, do or '?' at the location"},
		{name: "else", src: "  else {", line: 1, col: 3, wantReason: "no if, while, for, switch, do or '?' at the location"},
		// the parentheses
		{name: "if without parentheses", src: "  if x > 0 {", line: 1, col: 3, wantReason: "the controlling expression is not enclosed in parentheses on the line of the if"},
		{name: "if with parenthesis on the next line", src: "  if\n  (x > 0) {", line: 1, col: 3, wantReason: "the controlling expression is not enclosed in parentheses on the line of the if"},
		{name: "if with condition over several lines", src: "  if (x > 0 &&\n  y) {", line: 1, col: 3, wantReason: "the controlling expression is not enclosed in parentheses on the line of the if"},
		{name: "while with unbalanced parentheses", src: "  while (f(x) {", line: 1, col: 3, wantReason: "the controlling expression is not enclosed in parentheses on the line of the while"},
		{name: "switch at the end of the program", src: "  switch", line: 1, col: 3, wantReason: "the controlling expression is not enclosed in parentheses on the line of the switch"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := newMatcher(tt.src, nil, modelLP64)
			c, reason := m.findConstruct(witness.Location{Line: tt.line, Column: tt.col})
			if reason != tt.wantReason {
				t.Fatalf("reason = %q, want %q", reason, tt.wantReason)
			}
			if reason != "" {
				return
			}
			if c.kind != tt.wantKind {
				t.Errorf("kind = %q, want %q", c.kind, tt.wantKind)
			}
			if got := tt.src[c.exprStart:c.exprEnd]; got != tt.wantExpr {
				t.Errorf("controlling expression = %q, want %q", got, tt.wantExpr)
			}
		})
	}
}

// Waypoints with and without column must resolve to the same construct.
func TestFindConstructPosition(t *testing.T) {
	src := "int main() {\n  } else if (y) {\n"
	m := newMatcher(src, nil, modelLP64)
	withColumn, reason1 := m.findConstruct(witness.Location{Line: 2, Column: 10})
	withoutColumn, reason2 := m.findConstruct(witness.Location{Line: 2})
	if reason1 != "" || reason2 != "" {
		t.Fatalf("reasons: %q, %q", reason1, reason2)
	}
	if withColumn != withoutColumn {
		t.Errorf("constructs differ: %+v and %+v", withColumn, withoutColumn)
	}
	if line, column := m.src.position(withColumn.pos); line != 2 || column != 10 {
		t.Errorf("position = %d:%d, want 2:10", line, column)
	}
}

func TestAnalyzeCondition(t *testing.T) {
	const notSupported = "the controlling expression is not a nondet call, a negated nondet call, or a comparison of a nondet call with a decimal integer literal"
	const shortCircuit = "the controlling expression contains && or ||, so the witness does not say which operand decided the outcome"
	const notOnlyCode = "the controlling expression contains a comment, a string literal or a character literal"
	tests := []struct {
		expr         string
		wantForm     conditionForm
		wantType     string
		wantOp       string
		wantConstant string
		wantCall     string
		wantReason   string
	}{
		// form (i)
		{expr: "__VERIFIER_nondet_int()", wantForm: formCall, wantType: "int", wantCall: "__VERIFIER_nondet_int()"},
		{expr: "__VERIFIER_nondet_uchar(void)", wantForm: formCall, wantType: "uchar", wantCall: "__VERIFIER_nondet_uchar(void)"},
		{expr: "  __VERIFIER_nondet_bool ( void )\t", wantForm: formCall, wantType: "bool", wantCall: "__VERIFIER_nondet_bool ( void )"},
		{expr: "(__VERIFIER_nondet_int())", wantForm: formCall, wantType: "int", wantCall: "__VERIFIER_nondet_int()"},
		{expr: " ( ( (__VERIFIER_nondet_int()) ) ) ", wantForm: formCall, wantType: "int", wantCall: "__VERIFIER_nondet_int()"},
		// form (ii)
		{expr: "!__VERIFIER_nondet_int()", wantForm: formNegatedCall, wantType: "int", wantCall: "__VERIFIER_nondet_int()"},
		{expr: "! __VERIFIER_nondet_int()", wantForm: formNegatedCall, wantType: "int", wantCall: "__VERIFIER_nondet_int()"},
		{expr: "(!__VERIFIER_nondet_double())", wantForm: formNegatedCall, wantType: "double", wantCall: "__VERIFIER_nondet_double()"},
		// form (iii)
		{expr: "__VERIFIER_nondet_int() == 5", wantForm: formComparison, wantType: "int", wantOp: "==", wantConstant: "5", wantCall: "__VERIFIER_nondet_int()"},
		{expr: "__VERIFIER_nondet_int()!=5", wantForm: formComparison, wantType: "int", wantOp: "!=", wantConstant: "5", wantCall: "__VERIFIER_nondet_int()"},
		{expr: "__VERIFIER_nondet_int() < 0", wantForm: formComparison, wantType: "int", wantOp: "<", wantConstant: "0", wantCall: "__VERIFIER_nondet_int()"},
		{expr: "__VERIFIER_nondet_int() <= -1", wantForm: formComparison, wantType: "int", wantOp: "<=", wantConstant: "-1", wantCall: "__VERIFIER_nondet_int()"},
		{expr: "__VERIFIER_nondet_int() > 100", wantForm: formComparison, wantType: "int", wantOp: ">", wantConstant: "100", wantCall: "__VERIFIER_nondet_int()"},
		{expr: "__VERIFIER_nondet_ulong(void) >= 18446744073709551615", wantForm: formComparison, wantType: "ulong", wantOp: ">=", wantConstant: "18446744073709551615", wantCall: "__VERIFIER_nondet_ulong(void)"},
		{expr: "(__VERIFIER_nondet_int() <-1)", wantForm: formComparison, wantType: "int", wantOp: "<", wantConstant: "-1", wantCall: "__VERIFIER_nondet_int()"},
		{expr: "5 == __VERIFIER_nondet_int()", wantForm: formComparison, wantType: "int", wantOp: "==", wantConstant: "5", wantCall: "__VERIFIER_nondet_int()"},
		{expr: "5 != __VERIFIER_nondet_int()", wantForm: formComparison, wantType: "int", wantOp: "!=", wantConstant: "5", wantCall: "__VERIFIER_nondet_int()"},
		{expr: "0 < __VERIFIER_nondet_int()", wantForm: formComparison, wantType: "int", wantOp: ">", wantConstant: "0", wantCall: "__VERIFIER_nondet_int()"},
		{expr: "0<=__VERIFIER_nondet_int()", wantForm: formComparison, wantType: "int", wantOp: ">=", wantConstant: "0", wantCall: "__VERIFIER_nondet_int()"},
		{expr: "-7 > __VERIFIER_nondet_long()", wantForm: formComparison, wantType: "long", wantOp: "<", wantConstant: "-7", wantCall: "__VERIFIER_nondet_long()"},
		{expr: "((10 >= __VERIFIER_nondet_short()))", wantForm: formComparison, wantType: "short", wantOp: "<=", wantConstant: "10", wantCall: "__VERIFIER_nondet_short()"},
		// short-circuit operators
		{expr: "__VERIFIER_nondet_int() && x", wantReason: shortCircuit},
		{expr: "x || __VERIFIER_nondet_int()", wantReason: shortCircuit},
		{expr: "__VERIFIER_nondet_int() > 0 && __VERIFIER_nondet_int() < 5", wantReason: shortCircuit},
		{expr: "(__VERIFIER_nondet_int()) || (y)", wantReason: shortCircuit},
		// everything else
		{expr: "", wantReason: notSupported},
		{expr: "   ", wantReason: notSupported},
		{expr: "()", wantReason: notSupported},
		{expr: "x", wantReason: notSupported},
		{expr: "x > 0", wantReason: notSupported},
		{expr: "1", wantReason: notSupported},
		{expr: "__VERIFIER_nondet_int() ? 1 : 0", wantReason: notSupported},
		{expr: "f(), __VERIFIER_nondet_int()", wantReason: notSupported},
		{expr: "__VERIFIER_nondet_int(), 1", wantReason: notSupported},
		{expr: "__VERIFIER_nondet_int() == __VERIFIER_nondet_int()", wantReason: notSupported},
		{expr: "__VERIFIER_nondet_int() + 1 > 0", wantReason: notSupported},
		{expr: "__VERIFIER_nondet_int() % 2 == 0", wantReason: notSupported},
		{expr: "__VERIFIER_nondet_int() > 0 == 1", wantReason: notSupported},
		{expr: "0 < __VERIFIER_nondet_int() < 5", wantReason: notSupported},
		{expr: "__VERIFIER_nondet_int() & 1", wantReason: notSupported},
		{expr: "__VERIFIER_nondet_int() | 1", wantReason: notSupported},
		{expr: "__VERIFIER_nondet_int() >> 1", wantReason: notSupported},
		{expr: "__VERIFIER_nondet_int() << 1", wantReason: notSupported},
		{expr: "__VERIFIER_nondet_int() = 5", wantReason: notSupported},
		{expr: "__VERIFIER_nondet_int() >= x", wantReason: notSupported},
		{expr: "__VERIFIER_nondet_int() > 0x10", wantReason: notSupported},
		{expr: "__VERIFIER_nondet_int() > 010", wantReason: notSupported},
		{expr: "__VERIFIER_nondet_int() > 5u", wantReason: notSupported},
		{expr: "__VERIFIER_nondet_int() > 5L", wantReason: notSupported},
		{expr: "__VERIFIER_nondet_int() > +5", wantReason: notSupported},
		{expr: "__VERIFIER_nondet_int() > - 5", wantReason: notSupported},
		{expr: "__VERIFIER_nondet_int() > --5", wantReason: notSupported},
		{expr: "__VERIFIER_nondet_int() > 1.5", wantReason: notSupported},
		// Comments and literals are blanked in the masked text. What is left
		// of the expression must not be taken for the expression.
		{expr: "__VERIFIER_nondet_int() > 'a'", wantReason: notOnlyCode},
		{expr: "__VERIFIER_nondet_int() == 'a'-96", wantReason: notOnlyCode},
		{expr: "__VERIFIER_nondet_int() == 'a' -96", wantReason: notOnlyCode},
		{expr: "__VERIFIER_nondet_int() == '\\''-96", wantReason: notOnlyCode},
		{expr: "__VERIFIER_nondet_int() > \"abc\"[0]", wantReason: notOnlyCode},
		{expr: "__VERIFIER_nondet_int() > sizeof \"abc\" 5", wantReason: notOnlyCode},
		{expr: "__VERIFIER_nondet_int() /* c */", wantReason: notOnlyCode},
		{expr: "__VERIFIER_nondet_int() == /* minus */ 5", wantReason: notOnlyCode},
		{expr: "/* c */ !__VERIFIER_nondet_int()", wantReason: notOnlyCode},
		{expr: "(__VERIFIER_nondet_int() > 0 /* c */)", wantReason: notOnlyCode},
		{expr: "__VERIFIER_nondet_int() == 5 // c", wantReason: notOnlyCode},
		{expr: "__VERIFIER_nondet_int() && c == 'a'", wantReason: notOnlyCode},
		{expr: "x == 'a'", wantReason: notOnlyCode},
		{expr: "__VERIFIER_nondet_int() > (0)", wantReason: notSupported},
		{expr: "(__VERIFIER_nondet_int()) > 0", wantReason: notSupported},
		{expr: "0x10 < __VERIFIER_nondet_int()", wantReason: notSupported},
		{expr: "!(__VERIFIER_nondet_int())", wantReason: notSupported},
		{expr: "!!__VERIFIER_nondet_int()", wantReason: notSupported},
		{expr: "!__VERIFIER_nondet_int() == 0", wantReason: notSupported},
		{expr: "~__VERIFIER_nondet_int()", wantReason: notSupported},
		{expr: "-__VERIFIER_nondet_int() > 0", wantReason: notSupported},
		{expr: "(int)__VERIFIER_nondet_int()", wantReason: notSupported},
		{expr: "(int)(__VERIFIER_nondet_int())", wantReason: notSupported},
		{expr: "(__VERIFIER_nondet_int()) + (1)", wantReason: notSupported},
		{expr: "__VERIFIER_nondet_int(1)", wantReason: notSupported},
		{expr: "__VERIFIER_nondet_int", wantReason: notSupported},
		{expr: "x = __VERIFIER_nondet_int()", wantReason: notSupported},
		{expr: "(x = __VERIFIER_nondet_int()) != 0", wantReason: notSupported},
		{expr: "my__VERIFIER_nondet_int()", wantReason: notSupported},
		{expr: "__VERIFIER_nondet_int() == 5)", wantReason: notSupported},
		{expr: "(__VERIFIER_nondet_int() == 5", wantReason: notSupported},
		{expr: "*__VERIFIER_nondet_pointer()", wantReason: notSupported},
		{expr: "f(__VERIFIER_nondet_int())", wantReason: notSupported},
		{expr: "__VERIFIER_nondet_int() > 0\n", wantForm: formComparison, wantType: "int", wantOp: ">", wantConstant: "0", wantCall: "__VERIFIER_nondet_int()"},
	}
	for _, tt := range tests {
		t.Run(tt.expr, func(t *testing.T) {
			// The expression is embedded to check that offsets are absolute.
			const prefix = "if ("
			text := prefix + tt.expr + ") {"
			c, reason := analyzeCondition(newSourceText(text), len(prefix), len(prefix)+len(tt.expr))
			if reason != tt.wantReason {
				t.Fatalf("reason = %q, want %q", reason, tt.wantReason)
			}
			if reason != "" {
				return
			}
			if c.form != tt.wantForm || c.typeName != tt.wantType || c.op != tt.wantOp {
				t.Errorf("got form %v, type %q, op %q; want form %v, type %q, op %q",
					c.form, c.typeName, c.op, tt.wantForm, tt.wantType, tt.wantOp)
			}
			if tt.wantConstant != "" && (c.constant == nil || c.constant.String() != tt.wantConstant) {
				t.Errorf("constant = %v, want %s", c.constant, tt.wantConstant)
			}
			if got := text[c.callStart:c.callEnd]; got != tt.wantCall {
				t.Errorf("call = %q, want %q", got, tt.wantCall)
			}
		})
	}
}

func TestIntegerRange(t *testing.T) {
	tests := []struct {
		typeName string
		model    dataModel
		lo, hi   string
		known    bool
	}{
		{"char", modelLP64, "-128", "127", true},
		{"uchar", modelLP64, "0", "255", true},
		{"unsigned_char", modelLP64, "0", "255", true},
		{"u8", modelLP64, "0", "255", true},
		{"short", modelLP64, "-32768", "32767", true},
		{"ushort", modelLP64, "0", "65535", true},
		{"u16", modelLP64, "0", "65535", true},
		{"int", modelLP64, "-2147483648", "2147483647", true},
		{"int", modelILP32, "-2147483648", "2147483647", true},
		{"uint", modelLP64, "0", "4294967295", true},
		{"unsigned", modelILP32, "0", "4294967295", true},
		{"u32", modelLP64, "0", "4294967295", true},
		{"U32", modelLP64, "0", "4294967295", true},
		{"long", modelILP32, "-2147483648", "2147483647", true},
		{"long", modelLP64, "-9223372036854775808", "9223372036854775807", true},
		{"ulong", modelILP32, "0", "4294967295", true},
		{"ulong", modelLP64, "0", "18446744073709551615", true},
		{"longlong", modelILP32, "-9223372036854775808", "9223372036854775807", true},
		{"longlong", modelLP64, "-9223372036854775808", "9223372036854775807", true},
		{"ulonglong", modelILP32, "0", "18446744073709551615", true},
		{"ulonglong", modelLP64, "0", "18446744073709551615", true},
		{"bool", modelLP64, "0", "1", true},
		{"float", modelLP64, "", "", false},
		{"double", modelLP64, "", "", false},
		{"pointer", modelLP64, "", "", false},
		{"pchar", modelLP64, "", "", false},
		{"size_t", modelLP64, "", "", false},
		{"int128", modelLP64, "", "", false},
		{"Int", modelLP64, "", "", false},
		{"", modelLP64, "", "", false},
	}
	for _, tt := range tests {
		r, known := integerRange(tt.typeName, tt.model)
		if known != tt.known {
			t.Errorf("integerRange(%q, %v): known = %v, want %v", tt.typeName, tt.model, known, tt.known)
			continue
		}
		if known && (r.lo.String() != tt.lo || r.hi.String() != tt.hi) {
			t.Errorf("integerRange(%q, %v) = [%s, %s], want [%s, %s]", tt.typeName, tt.model, r.lo, r.hi, tt.lo, tt.hi)
		}
	}
}

func bigInt(t *testing.T, s string) *big.Int {
	t.Helper()
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		t.Fatalf("bad integer %q", s)
	}
	return v
}

func TestFormatCInteger(t *testing.T) {
	tests := []struct{ in, want string }{
		{"0", "0"},
		{"1", "1"},
		{"-1", "-1"},
		{"2147483647", "2147483647"},
		{"-2147483647", "-2147483647"},
		{"2147483648", "2147483648LL"},
		{"-2147483648", "-2147483648LL"},
		{"4294967295", "4294967295LL"},
		{"9223372036854775807", "9223372036854775807LL"},
		{"-9223372036854775807", "-9223372036854775807LL"},
		{"-9223372036854775808", "(-9223372036854775807LL - 1)"},
		{"9223372036854775808", "9223372036854775808ULL"},
		{"18446744073709551615", "18446744073709551615ULL"},
	}
	for _, tt := range tests {
		if got := formatCInteger(bigInt(t, tt.in)); got != tt.want {
			t.Errorf("formatCInteger(%s) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestBranchValue(t *testing.T) {
	call := func(typeName string) condition {
		return condition{form: formCall, typeName: typeName}
	}
	negated := func(typeName string) condition {
		return condition{form: formNegatedCall, typeName: typeName}
	}
	compare := func(typeName, op, constant string) condition {
		return condition{form: formComparison, typeName: typeName, op: op, constant: bigInt(t, constant)}
	}
	const noValue = "-"
	tests := []struct {
		name      string
		kind      string
		cond      condition
		model     dataModel
		wantTrue  string // value for a "true" waypoint, noValue if there is none
		wantFalse string
	}{
		// form (i)
		{"call int", "if", call("int"), modelLP64, "1", "0"},
		{"call bool", "while", call("bool"), modelLP64, "1", "0"},
		{"call uchar", "for", call("uchar"), modelLP64, "1", "0"},
		{"call ulonglong", "do", call("ulonglong"), modelLP64, "1", "0"},
		{"call float", "?", call("float"), modelLP64, "1", "0"},
		{"call double", "if", call("double"), modelLP64, "1", "0"},
		{"call pointer", "if", call("pointer"), modelLP64, noValue, noValue},
		{"call pchar", "if", call("pchar"), modelLP64, noValue, noValue},
		{"call unknown type", "if", call("foo"), modelLP64, noValue, noValue},
		// form (ii)
		{"negated int", "if", negated("int"), modelLP64, "0", "1"},
		{"negated bool", "while", negated("bool"), modelLP64, "0", "1"},
		{"negated double", "if", negated("double"), modelLP64, "0", "1"},
		{"negated pointer", "if", negated("pointer"), modelLP64, noValue, noValue},
		// form (iii)
		{"int == 5", "if", compare("int", "==", "5"), modelLP64, "5", "6"},
		{"int == max", "if", compare("int", "==", "2147483647"), modelLP64, "2147483647", "2147483646"},
		{"int != 5", "if", compare("int", "!=", "5"), modelLP64, "6", "5"},
		{"int != max", "if", compare("int", "!=", "2147483647"), modelLP64, "2147483646", "2147483647"},
		{"int < 5", "if", compare("int", "<", "5"), modelLP64, "4", "5"},
		{"int < min", "if", compare("int", "<", "-2147483648"), modelLP64, noValue, "-2147483648LL"},
		{"int <= 5", "if", compare("int", "<=", "5"), modelLP64, "5", "6"},
		{"int <= max", "if", compare("int", "<=", "2147483647"), modelLP64, "2147483647", noValue},
		{"int > 5", "if", compare("int", ">", "5"), modelLP64, "6", "5"},
		{"int > max", "if", compare("int", ">", "2147483647"), modelLP64, noValue, "2147483647"},
		{"int >= 5", "if", compare("int", ">=", "5"), modelLP64, "5", "4"},
		{"int >= min", "if", compare("int", ">=", "-2147483648"), modelLP64, "-2147483648LL", noValue},
		{"int > -1", "while", compare("int", ">", "-1"), modelLP64, "0", "-1"},
		{"int constant above the range", "if", compare("int", "<", "2147483648"), modelLP64, noValue, noValue},
		{"int constant below the range", "if", compare("int", ">", "-2147483649"), modelLP64, noValue, noValue},
		{"uint > 0", "if", compare("uint", ">", "0"), modelLP64, "1", "0"},
		{"uint < 0", "if", compare("uint", "<", "0"), modelLP64, noValue, "0"},
		{"uint >= 0", "if", compare("uint", ">=", "0"), modelLP64, "0", noValue},
		{"uint == 0", "if", compare("uint", "==", "0"), modelLP64, "0", "1"},
		{"uint != 0", "if", compare("uint", "!=", "0"), modelLP64, "1", "0"},
		{"uint == max", "if", compare("uint", "==", "4294967295"), modelLP64, "4294967295LL", "4294967294LL"},
		{"uint > -1", "if", compare("uint", ">", "-1"), modelLP64, noValue, noValue},
		{"uint < 4294967296", "if", compare("uint", "<", "4294967296"), modelLP64, noValue, noValue},
		{"unsigned <= 7", "if", compare("unsigned", "<=", "7"), modelLP64, "7", "8"},
		{"uchar > 255", "if", compare("uchar", ">", "255"), modelLP64, noValue, "255"},
		{"uchar == 255", "if", compare("uchar", "==", "255"), modelLP64, "255", "254"},
		{"uchar < 256", "if", compare("uchar", "<", "256"), modelLP64, noValue, noValue},
		{"char < -128", "if", compare("char", "<", "-128"), modelLP64, noValue, "-128"},
		{"char >= 127", "if", compare("char", ">=", "127"), modelLP64, "127", "126"},
		{"short > 32766", "if", compare("short", ">", "32766"), modelLP64, "32767", "32766"},
		{"ushort <= 65535", "if", compare("ushort", "<=", "65535"), modelLP64, "65535", noValue},
		{"bool == 1", "if", compare("bool", "==", "1"), modelLP64, "1", "0"},
		{"bool == 0", "if", compare("bool", "==", "0"), modelLP64, "0", "1"},
		{"bool != 0", "if", compare("bool", "!=", "0"), modelLP64, "1", "0"},
		{"bool > 1", "if", compare("bool", ">", "1"), modelLP64, noValue, "1"},
		{"bool == 2", "if", compare("bool", "==", "2"), modelLP64, noValue, noValue},
		{"long > int max, LP64", "if", compare("long", ">", "2147483647"), modelLP64, "2147483648LL", "2147483647"},
		{"long > int max, ILP32", "if", compare("long", ">", "2147483647"), modelILP32, noValue, "2147483647"},
		{"long == 2147483648, ILP32", "if", compare("long", "==", "2147483648"), modelILP32, noValue, noValue},
		{"long >= min, LP64", "if", compare("long", ">=", "-9223372036854775808"), modelLP64, "(-9223372036854775807LL - 1)", noValue},
		{"ulong == max, LP64", "if", compare("ulong", "==", "18446744073709551615"), modelLP64, "18446744073709551615ULL", "18446744073709551614ULL"},
		{"ulong == 4294967295, ILP32", "if", compare("ulong", "==", "4294967295"), modelILP32, "4294967295LL", "4294967294LL"},
		{"ulong > 4294967295, ILP32", "if", compare("ulong", ">", "4294967295"), modelILP32, noValue, "4294967295LL"},
		{"ulong > 4294967295, LP64", "if", compare("ulong", ">", "4294967295"), modelLP64, "4294967296LL", "4294967295LL"},
		{"longlong < max, ILP32", "if", compare("longlong", "<", "9223372036854775807"), modelILP32, "9223372036854775806LL", "9223372036854775807LL"},
		{"ulonglong > max, ILP32", "if", compare("ulonglong", ">", "18446744073709551615"), modelILP32, noValue, "18446744073709551615ULL"},
		{"float comparison", "if", compare("float", ">", "0"), modelLP64, noValue, noValue},
		{"double comparison", "if", compare("double", "==", "0"), modelLP64, noValue, noValue},
		{"pointer comparison", "if", compare("pointer", "!=", "0"), modelLP64, noValue, noValue},
		{"unknown type comparison", "if", compare("foo", "!=", "0"), modelLP64, noValue, noValue},
		// A switch has no outcome true or false.
		{"switch on call", "switch", call("int"), modelLP64, noValue, noValue},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for outcome, want := range map[string]string{"true": tt.wantTrue, "false": tt.wantFalse} {
				got, reason := tt.cond.valueFor(tt.kind, outcome, tt.model)
				if want == noValue {
					if reason == "" {
						t.Errorf("%s: got value %q, want none", outcome, got)
					}
					continue
				}
				if reason != "" || got != want {
					t.Errorf("%s: got value %q (reason %q), want %q", outcome, got, reason, want)
				}
			}
			// Values other than true and false are for switch only.
			for _, value := range []string{"default", "1", "0", ""} {
				if tt.kind == "switch" {
					continue
				}
				if got, reason := tt.cond.valueFor(tt.kind, value, tt.model); reason == "" {
					t.Errorf("waypoint value %q: got value %q, want none", value, got)
				}
			}
		})
	}
}

func TestSwitchValue(t *testing.T) {
	tests := []struct {
		name    string
		cond    condition
		model   dataModel
		value   string
		want    string // "" if there is no value
		wantWhy string // substring of the reason
	}{
		{name: "int", cond: condition{form: formCall, typeName: "int"}, value: "42", want: "42"},
		{name: "zero", cond: condition{form: formCall, typeName: "int"}, value: "0", want: "0"},
		{name: "negative", cond: condition{form: formCall, typeName: "int"}, value: "-1", want: "-1"},
		{name: "explicit sign", cond: condition{form: formCall, typeName: "int"}, value: "+7", want: "+7"},
		{name: "hexadecimal", cond: condition{form: formCall, typeName: "int"}, value: "0x10", want: "0x10"},
		{name: "octal", cond: condition{form: formCall, typeName: "uchar"}, value: "0377", want: "0377"},
		{name: "binary", cond: condition{form: formCall, typeName: "uchar"}, value: "0b101", want: "0b101"},
		{name: "suffix", cond: condition{form: formCall, typeName: "ulong"}, value: "10UL", want: "10UL"},
		{name: "suffix with ll first", cond: condition{form: formCall, typeName: "ulonglong"}, value: "10llu", want: "10llu"},
		{name: "repeated suffix", cond: condition{form: formCall, typeName: "uint"}, value: "10uu", wantWhy: "not an integer literal"},
		{name: "suffix that is not one of C", cond: condition{form: formCall, typeName: "ulong"}, value: "10lul", wantWhy: "not an integer literal"},
		{name: "suffix ll in mixed case", cond: condition{form: formCall, typeName: "longlong"}, value: "10lL", wantWhy: "not an integer literal"},
		{name: "uchar max", cond: condition{form: formCall, typeName: "uchar"}, value: "255", want: "255"},
		{name: "char", cond: condition{form: formCall, typeName: "char"}, value: "-128", want: "-128"},
		{name: "long LP64", cond: condition{form: formCall, typeName: "long"}, value: "4294967296", want: "4294967296"},
		{name: "long ILP32", cond: condition{form: formCall, typeName: "long"}, model: modelILP32, value: "4294967296", wantWhy: "outside the range"},
		{name: "uchar above the range", cond: condition{form: formCall, typeName: "uchar"}, value: "256", wantWhy: "outside the range"},
		{name: "octal above the range", cond: condition{form: formCall, typeName: "uchar"}, value: "0400", wantWhy: "outside the range"},
		{name: "uint below the range", cond: condition{form: formCall, typeName: "uint"}, value: "-1", wantWhy: "outside the range"},
		{name: "default", cond: condition{form: formCall, typeName: "int"}, value: "default", wantWhy: "does not determine an input value"},
		{name: "true", cond: condition{form: formCall, typeName: "int"}, value: "true", wantWhy: "not an integer literal"},
		{name: "false", cond: condition{form: formCall, typeName: "int"}, value: "false", wantWhy: "not an integer literal"},
		{name: "not a literal", cond: condition{form: formCall, typeName: "int"}, value: "1; system(\"id\")", wantWhy: "not an integer literal"},
		{name: "float literal", cond: condition{form: formCall, typeName: "int"}, value: "1.0", wantWhy: "not an integer literal"},
		{name: "empty", cond: condition{form: formCall, typeName: "int"}, value: "", wantWhy: "not an integer literal"},
		{name: "bool", cond: condition{form: formCall, typeName: "bool"}, value: "1", wantWhy: "not an integer type"},
		{name: "float", cond: condition{form: formCall, typeName: "float"}, value: "1", wantWhy: "not an integer type"},
		{name: "double", cond: condition{form: formCall, typeName: "double"}, value: "1", wantWhy: "not an integer type"},
		{name: "pointer", cond: condition{form: formCall, typeName: "pointer"}, value: "0", wantWhy: "not an integer type"},
		{name: "unknown type", cond: condition{form: formCall, typeName: "foo"}, value: "0", wantWhy: "not an integer type"},
		{name: "negated call", cond: condition{form: formNegatedCall, typeName: "int"}, value: "1", wantWhy: "not a plain nondet call"},
		{name: "comparison", cond: condition{form: formComparison, typeName: "int", op: "==", constant: big.NewInt(1)}, value: "1", wantWhy: "not a plain nondet call"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, reason := tt.cond.valueFor("switch", tt.value, tt.model)
			if tt.want != "" {
				if reason != "" || got != tt.want {
					t.Errorf("got value %q (reason %q), want %q", got, reason, tt.want)
				}
				return
			}
			if reason == "" || !strings.Contains(reason, tt.wantWhy) {
				t.Errorf("got value %q, reason %q; want no value and a reason containing %q", got, reason, tt.wantWhy)
			}
		})
	}
}

func TestBranchingMatched(t *testing.T) {
	tests := []struct {
		name       string
		src        string
		model      string
		branchings []witness.Branching
		wantValues string
		wantCall   string // the rewritten line, "" to skip the check
	}{
		{
			name:       "if taken",
			src:        lines("int main() {", "  if (__VERIFIER_nondet_int()) {", "    return 1;", "  }", "}"),
			branchings: []witness.Branching{branch(2, 3, "true")},
			wantValues: "1",
			wantCall:   "  if (__VERIFIER_nondet_value_injection_2_29()) {",
		},
		{
			name:       "if not taken",
			src:        lines("int main() {", "  if (__VERIFIER_nondet_int()) {", "    return 1;", "  }", "}"),
			branchings: []witness.Branching{branch(2, 3, "false")},
			wantValues: "0",
		},
		{
			name:       "if with negated call",
			src:        lines("int main() {", "  if (!__VERIFIER_nondet_bool()) {", "    return 1;", "  }", "}"),
			branchings: []witness.Branching{branch(2, 3, "true")},
			wantValues: "0",
		},
		{
			name:       "else if with unspecified column",
			src:        lines("int main() {", "  if (x) {", "  } else if (__VERIFIER_nondet_uchar(void) >= 200) {", "  }", "}"),
			branchings: []witness.Branching{branch(3, 0, "true")},
			wantValues: "200",
		},
		{
			name:       "while taken twice, then left",
			src:        lines("int main() {", "  while (__VERIFIER_nondet_int() > 0) {", "    n++;", "  }", "}"),
			branchings: []witness.Branching{branch(2, 3, "true"), branch(2, 3, "true"), branch(2, 3, "false")},
			wantValues: "1, 1, 0",
		},
		{
			name:       "for",
			src:        lines("int main() {", "  for (;__VERIFIER_nondet_int() != 3;) {", "    n++;", "  }", "}"),
			branchings: []witness.Branching{branch(2, 3, "true"), branch(2, 3, "false")},
			wantValues: "4, 3",
			wantCall:   "  for (;__VERIFIER_nondet_value_injection_2_31() != 3;) {",
		},
		{
			name:       "for with all clauses",
			src:        lines("int main() {", "  for (i = 0; 10 > __VERIFIER_nondet_short(); i++) {", "    n++;", "  }", "}"),
			branchings: []witness.Branching{branch(2, 0, "false"), branch(2, 0, "true")},
			wantValues: "10, 9",
		},
		{
			name:       "do while",
			src:        lines("int main() {", "  do {", "    n++;", "  } while (__VERIFIER_nondet_bool());", "}"),
			branchings: []witness.Branching{branch(2, 3, "true"), branch(2, 3, "false")},
			wantValues: "1, 0",
			wantCall:   "  } while (__VERIFIER_nondet_value_injection_4_35());",
		},
		{
			name:       "switch",
			src:        lines("int main() {", "  switch (__VERIFIER_nondet_int()) {", "  case 7: return 1;", "  }", "}"),
			branchings: []witness.Branching{branch(2, 3, "7"), branch(2, 0, "-1"), branch(2, 3, "0x10")},
			wantValues: "7, -1, 0x10",
		},
		{
			name:       "conditional operator",
			src:        lines("int main() {", "  x = __VERIFIER_nondet_int() ? 10 : 20;", "}"),
			branchings: []witness.Branching{branch(2, 31, "true")},
			wantValues: "1",
			wantCall:   "  x = __VERIFIER_nondet_value_injection_2_29() ? 10 : 20;",
		},
		{
			name:       "conditional operator with unspecified column",
			src:        lines("int main() {", "  x = (__VERIFIER_nondet_int() <= 4) ? 10 : 20;", "}"),
			branchings: []witness.Branching{branch(2, 0, "false")},
			wantValues: "5",
		},
		{
			name:       "mirrored comparison",
			src:        lines("int main() {", "  if (0 < __VERIFIER_nondet_int()) {", "    return 1;", "  }", "}"),
			branchings: []witness.Branching{branch(2, 3, "true"), branch(2, 3, "false")},
			wantValues: "1, 0",
		},
		{
			name:       "waypoints with and without column refer to the same construct",
			src:        lines("int main() {", "  while (__VERIFIER_nondet_int()) {", "    n++;", "  }", "}"),
			branchings: []witness.Branching{branch(2, 0, "true"), branch(2, 3, "true"), branch(2, 0, "false")},
			wantValues: "1, 1, 0",
		},
		{
			name:       "unsigned comparison",
			src:        lines("int main() {", "  while (__VERIFIER_nondet_uint() >= 10) {", "    n++;", "  }", "}"),
			branchings: []witness.Branching{branch(2, 3, "true"), branch(2, 3, "false")},
			wantValues: "10, 9",
		},
		{
			name:       "long in LP64",
			src:        lines("int main() {", "  if (__VERIFIER_nondet_long() > 2147483647) {", "    return 1;", "  }", "}"),
			model:      "LP64",
			branchings: []witness.Branching{branch(2, 3, "true")},
			wantValues: "2147483648LL",
		},
		{
			name:       "long in ILP32",
			src:        lines("int main() {", "  if (__VERIFIER_nondet_long() > 2147483646) {", "    return 1;", "  }", "}"),
			model:      "ILP32",
			branchings: []witness.Branching{branch(2, 3, "true")},
			wantValues: "2147483647",
		},
		{
			name:       "comment and string outside the condition do not confuse the scanner",
			src:        lines("int main() {", "  puts(\"if (\"); /* while ( */ if (__VERIFIER_nondet_int() ) /* ) */ { // )", "    return 1;", "  }", "}"),
			branchings: []witness.Branching{branch(2, 0, "true")},
			wantValues: "1",
		},
		{
			name:       "comparison next to a character literal outside the condition",
			src:        lines("int main() {", "  c = 'a'-96; if (__VERIFIER_nondet_int() == -96) { c = 'b'; }", "}"),
			branchings: []witness.Branching{branch(2, 15, "true")},
			wantValues: "-96",
		},
		{
			name:       "for with character literals in the other clauses",
			src:        lines("int main() {", "  for (c = 'a'; __VERIFIER_nondet_int() != 3; c += 'b' - 'a') {", "    n++;", "  }", "}"),
			branchings: []witness.Branching{branch(2, 3, "true"), branch(2, 3, "false")},
			wantValues: "4, 3",
		},
		{
			name:       "conditional operator with literals in the other operands",
			src:        lines("int main() {", "  s = (__VERIFIER_nondet_int() <= 4) ? \"yes\" /* c */ : \"no\";", "}"),
			branchings: []witness.Branching{branch(2, 0, "false")},
			wantValues: "5",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := mustInstrument(t, tt.src, &witness.Witness{Branchings: tt.branchings}, Options{Model: tt.model})
			checkInjection(t, tt.src, res, tt.wantValues, nil)
			if tt.wantCall != "" && !strings.Contains(res.Source, "\n"+tt.wantCall+"\n") {
				t.Errorf("Source should contain the line %q.\ngot:\n%s", tt.wantCall, res.Source)
			}
		})
	}
}

func TestBranchingNotMatched(t *testing.T) {
	tests := []struct {
		name       string
		src        string
		model      string
		branchings []witness.Branching
		wantNotes  []string
	}{
		{
			name:       "no branching at the location",
			src:        lines("int main() {", "  if (__VERIFIER_nondet_int()) {", "    return 1;", "  }", "}"),
			branchings: []witness.Branching{branch(3, 5, "true")},
			wantNotes:  []string{"branching at 3:5 (true) not matched: no if, while, for, switch, do or '?' at the location"},
		},
		{
			name:       "no branching on the line",
			src:        lines("int main() {", "  if (__VERIFIER_nondet_int()) {", "    return 1;", "  }", "}"),
			branchings: []witness.Branching{branch(3, 0, "false")},
			wantNotes:  []string{"branching at 3 (false) not matched: no if, while, for, switch, do or '?' on the line"},
		},
		{
			name:       "line beyond the program",
			src:        lines("int main() {", "  if (__VERIFIER_nondet_int()) {", "    return 1;", "  }", "}"),
			branchings: []witness.Branching{branch(77, 3, "true")},
			wantNotes:  []string{"branching at 77:3 (true) not matched: line 77 does not exist"},
		},
		{
			name:       "condition over several lines",
			src:        lines("int main() {", "  if (__VERIFIER_nondet_int()", "      ) {", "    return 1;", "  }", "}"),
			branchings: []witness.Branching{branch(2, 3, "true")},
			wantNotes:  []string{"branching at 2:3 (true) not matched: the controlling expression is not enclosed in parentheses on the line of the if"},
		},
		{
			name:       "condition with &&",
			src:        lines("int main() {", "  if (__VERIFIER_nondet_int() && __VERIFIER_nondet_int()) {", "    return 1;", "  }", "}"),
			branchings: []witness.Branching{branch(2, 3, "true")},
			wantNotes:  []string{"branching at 2:3 (if, 1 waypoint) not matched: " + reasonShortCircuit},
		},
		{
			name:       "condition with ||",
			src:        lines("int main() {", "  while (x || __VERIFIER_nondet_int()) {", "    return 1;", "  }", "}"),
			branchings: []witness.Branching{branch(2, 3, "true"), branch(2, 3, "false")},
			wantNotes:  []string{"branching at 2:3 (while, 2 waypoints) not matched: " + reasonShortCircuit},
		},
		{
			name:       "condition without nondet call",
			src:        lines("int main() {", "  if (x > 0) {", "    return 1;", "  }", "}"),
			branchings: []witness.Branching{branch(2, 0, "true")},
			// Not worth a note: the waypoint says nothing about input values.
			wantNotes: nil,
		},
		{
			name:       "condition with two nondet calls",
			src:        lines("int main() {", "  if (__VERIFIER_nondet_int() == __VERIFIER_nondet_int()) {", "    return 1;", "  }", "}"),
			branchings: []witness.Branching{branch(2, 3, "true")},
			wantNotes:  []string{"branching at 2:3 (if, 1 waypoint) not matched: " + reasonUnsupportedCondition},
		},
		{
			name:       "condition with arithmetic",
			src:        lines("int main() {", "  if (__VERIFIER_nondet_int() % 2 == 0) {", "    return 1;", "  }", "}"),
			branchings: []witness.Branching{branch(2, 3, "true")},
			wantNotes:  []string{"branching at 2:3 (if, 1 waypoint) not matched: " + reasonUnsupportedCondition},
		},
		{
			name:       "condition with comma",
			src:        lines("int main() {", "  if (x++, __VERIFIER_nondet_int()) {", "    return 1;", "  }", "}"),
			branchings: []witness.Branching{branch(2, 3, "true")},
			wantNotes:  []string{"branching at 2:3 (if, 1 waypoint) not matched: " + reasonUnsupportedCondition},
		},
		{
			name:       "condition with nested conditional operator",
			src:        lines("int main() {", "  if (__VERIFIER_nondet_int() ? a : b) {", "    return 1;", "  }", "}"),
			branchings: []witness.Branching{branch(2, 3, "true")},
			wantNotes:  []string{"branching at 2:3 (if, 1 waypoint) not matched: " + reasonUnsupportedCondition},
		},
		{
			name:       "for without condition",
			src:        lines("int main() {", "  for (;;) {", "    if (__VERIFIER_nondet_int()) { break; }", "  }", "}"),
			branchings: []witness.Branching{branch(2, 3, "true")},
			wantNotes:  nil,
		},
		{
			name:       "needed value is not representable in the unsigned type",
			src:        lines("int main() {", "  if (__VERIFIER_nondet_uint() < 0) {", "    return 1;", "  }", "}"),
			branchings: []witness.Branching{branch(2, 3, "true")},
			wantNotes:  []string{`branching at 2:3 (if, 1 waypoint) not matched: no value of nondet type "uint" makes the comparison < 0 true`},
		},
		{
			name:       "one unrepresentable outcome discards all waypoints of the loop",
			src:        lines("int main() {", "  while (__VERIFIER_nondet_uint() >= 0) {", "    n++;", "  }", "}"),
			branchings: []witness.Branching{branch(2, 3, "true"), branch(2, 3, "true"), branch(2, 3, "false")},
			wantNotes:  []string{`branching at 2:3 (while, 3 waypoints) not matched: no value of nondet type "uint" makes the comparison >= 0 false`},
		},
		{
			name:       "constant outside the range of the type",
			src:        lines("int main() {", "  if (__VERIFIER_nondet_uchar() < 256) {", "    return 1;", "  }", "}"),
			branchings: []witness.Branching{branch(2, 3, "true")},
			wantNotes:  []string{`branching at 2:3 (if, 1 waypoint) not matched: constant 256 is outside the range of nondet type "uchar"`},
		},
		{
			name:       "long in ILP32",
			src:        lines("int main() {", "  if (__VERIFIER_nondet_long() > 2147483647) {", "    return 1;", "  }", "}"),
			model:      "ILP32",
			branchings: []witness.Branching{branch(2, 3, "true")},
			wantNotes:  []string{`branching at 2:3 (if, 1 waypoint) not matched: no value of nondet type "long" makes the comparison > 2147483647 true`},
		},
		{
			name:       "comparison of a float",
			src:        lines("int main() {", "  if (__VERIFIER_nondet_float() > 0) {", "    return 1;", "  }", "}"),
			branchings: []witness.Branching{branch(2, 3, "true")},
			wantNotes:  []string{`branching at 2:3 (if, 1 waypoint) not matched: nondet type "float" is not an integer type with known range`},
		},
		{
			name:       "pointer as condition",
			src:        lines("int main() {", "  if (__VERIFIER_nondet_pointer()) {", "    return 1;", "  }", "}"),
			branchings: []witness.Branching{branch(2, 3, "true")},
			wantNotes:  []string{`branching at 2:3 (if, 1 waypoint) not matched: nondet type "pointer" is not supported for branching waypoints`},
		},
		{
			name:       "integer value for an if",
			src:        lines("int main() {", "  if (__VERIFIER_nondet_int()) {", "    return 1;", "  }", "}"),
			branchings: []witness.Branching{branch(2, 3, "5")},
			wantNotes:  []string{`branching at 2:3 (if, 1 waypoint) not matched: waypoint value "5" is neither true nor false`},
		},
		{
			name:       "default for a loop",
			src:        lines("int main() {", "  while (__VERIFIER_nondet_int()) {", "    return 1;", "  }", "}"),
			branchings: []witness.Branching{branch(2, 3, "true"), branch(2, 3, "default")},
			wantNotes:  []string{`branching at 2:3 (while, 2 waypoints) not matched: waypoint value "default" is neither true nor false`},
		},
		{
			name:       "default discards all waypoints of the switch",
			src:        lines("int main() {", "  switch (__VERIFIER_nondet_int()) {", "  case 1: return 1;", "  }", "}"),
			branchings: []witness.Branching{branch(2, 3, "1"), branch(2, 3, "default"), branch(2, 3, "2")},
			wantNotes:  []string{"branching at 2:3 (switch, 3 waypoints) not matched: waypoint value default does not determine an input value"},
		},
		{
			name:       "true for a switch",
			src:        lines("int main() {", "  switch (__VERIFIER_nondet_int()) {", "  case 1: return 1;", "  }", "}"),
			branchings: []witness.Branching{branch(2, 3, "true")},
			wantNotes:  []string{`branching at 2:3 (switch, 1 waypoint) not matched: waypoint value "true" is not an integer literal`},
		},
		{
			name:       "switch on a comparison",
			src:        lines("int main() {", "  switch (__VERIFIER_nondet_int() > 0) {", "  case 1: return 1;", "  }", "}"),
			branchings: []witness.Branching{branch(2, 3, "1")},
			wantNotes:  []string{"branching at 2:3 (switch, 1 waypoint) not matched: the controlling expression of the switch is not a plain nondet call"},
		},
		{
			name:       "switch on a bool",
			src:        lines("int main() {", "  switch (__VERIFIER_nondet_bool()) {", "  case 1: return 1;", "  }", "}"),
			branchings: []witness.Branching{branch(2, 3, "1")},
			wantNotes:  []string{`branching at 2:3 (switch, 1 waypoint) not matched: nondet type "bool" is not an integer type with known range`},
		},
		{
			name:       "switch value outside the range of the type",
			src:        lines("int main() {", "  switch (__VERIFIER_nondet_uchar()) {", "  case 1: return 1;", "  }", "}"),
			branchings: []witness.Branching{branch(2, 3, "256")},
			wantNotes:  []string{`branching at 2:3 (switch, 1 waypoint) not matched: waypoint value 256 is outside the range of nondet type "uchar"`},
		},
		{
			name:       "nondet call that is not a recognized call site",
			src:        lines("int main() {", "  return __VERIFIER_nondet_int() ? 1 : 2;", "}"),
			branchings: []witness.Branching{branch(2, 34, "true")},
			wantNotes:  []string{"branching at 2:34 (?:, 1 waypoint) not matched: the nondet call of the controlling expression is not a recognized call site"},
		},
		{
			name:       "conditional operator whose condition may be larger",
			src:        lines("int main() {", "  x = y + __VERIFIER_nondet_int() ? 1 : 2;", "}"),
			branchings: []witness.Branching{branch(2, 0, "true")},
			wantNotes:  []string{"branching at 2 (true) not matched: " + reasonConditionalContext},
		},
		{
			// Blanking the literal leaves "__VERIFIER_nondet_int() == -96".
			name:       "comparison with an expression that starts with a character literal",
			src:        lines("int main() {", "  if (__VERIFIER_nondet_int() == 'a'-96) {", "    return 1;", "  }", "}"),
			branchings: []witness.Branching{branch(2, 3, "true")},
			wantNotes:  []string{"branching at 2:3 (if, 1 waypoint) not matched: " + reasonConditionNotOnlyCode},
		},
		{
			name:       "loop condition with a character literal",
			src:        lines("int main() {", "  while (__VERIFIER_nondet_char() != 'x' -7) {", "    n++;", "  }", "}"),
			branchings: []witness.Branching{branch(2, 0, "true"), branch(2, 0, "false")},
			wantNotes:  []string{"branching at 2:3 (while, 2 waypoints) not matched: " + reasonConditionNotOnlyCode},
		},
		{
			name:       "for condition with a character literal",
			src:        lines("int main() {", "  for (;__VERIFIER_nondet_int() < 'a'-96;) {", "    n++;", "  }", "}"),
			branchings: []witness.Branching{branch(2, 3, "false")},
			wantNotes:  []string{"branching at 2:3 (for, 1 waypoint) not matched: " + reasonConditionNotOnlyCode},
		},
		{
			name:       "conditional operator with a character literal in the condition",
			src:        lines("int main() {", "  x = (__VERIFIER_nondet_int() == 'a'-96) ? 1 : 2;", "}"),
			branchings: []witness.Branching{branch(2, 0, "true")},
			wantNotes:  []string{"branching at 2:43 (?:, 1 waypoint) not matched: " + reasonConditionNotOnlyCode},
		},
		{
			name:       "comment inside the condition",
			src:        lines("int main() {", "  if (__VERIFIER_nondet_int() /* ) */ ) {", "    return 1;", "  }", "}"),
			branchings: []witness.Branching{branch(2, 3, "true")},
			wantNotes:  []string{"branching at 2:3 (if, 1 waypoint) not matched: " + reasonConditionNotOnlyCode},
		},
		{
			name:       "comment between the operands of the comparison",
			src:        lines("int main() {", "  if (__VERIFIER_nondet_int() == /* minus */ 5) {", "    return 1;", "  }", "}"),
			branchings: []witness.Branching{branch(2, 3, "true")},
			wantNotes:  []string{"branching at 2:3 (if, 1 waypoint) not matched: " + reasonConditionNotOnlyCode},
		},
		{
			name:       "string literal inside the condition",
			src:        lines("int main() {", "  if (__VERIFIER_nondet_int() == \"\\5\"[0]-5) {", "    return 1;", "  }", "}"),
			branchings: []witness.Branching{branch(2, 3, "true")},
			wantNotes:  []string{"branching at 2:3 (if, 1 waypoint) not matched: " + reasonConditionNotOnlyCode},
		},
		{
			name:       "conditional operator whose condition starts the line and continues the previous line",
			src:        lines("int main() {", "  x = a +", "    __VERIFIER_nondet_int() ? 1 : 2;", "}"),
			branchings: []witness.Branching{branch(3, 29, "true")},
			wantNotes:  []string{"branching at 3:29 (true) not matched: " + reasonConditionalContext},
		},
		{
			name:       "conditional operator whose condition starts the line, unspecified column",
			src:        lines("int main() {", "  x = a +", "    __VERIFIER_nondet_int() ? 1 : 2;", "}"),
			branchings: []witness.Branching{branch(3, 0, "false")},
			wantNotes:  []string{"branching at 3 (false) not matched: " + reasonConditionalContext},
		},
		{
			name:       "two constructs with the same nondet call",
			src:        lines("int main() {", "  do {", "    n++;", "  } while (__VERIFIER_nondet_int());", "}"),
			branchings: []witness.Branching{branch(2, 3, "true"), branch(4, 5, "true"), branch(2, 3, "false")},
			wantNotes: []string{
				"branching at 2:3 (do, 2 waypoints) not matched: several branching constructs refer to the nondet call site at 4:34",
				"branching at 4:5 (while, 1 waypoint) not matched: several branching constructs refer to the nondet call site at 4:34",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := mustInstrument(t, tt.src, &witness.Witness{Branchings: tt.branchings}, Options{Model: tt.model})
			if res.InjectedSites != 0 || res.Source != tt.src {
				t.Errorf("no call site may be instrumented (InjectedSites = %d).\ngot:\n%s", res.InjectedSites, res.Source)
			}
			if strings.Join(res.Notes, "\n") != strings.Join(tt.wantNotes, "\n") {
				t.Errorf("notes:\n%s\nwant:\n%s", strings.Join(res.Notes, "\n"), strings.Join(tt.wantNotes, "\n"))
			}
		})
	}
}

func TestBranchingsOfSeveralConstructs(t *testing.T) {
	src := lines(
		"int main() {", // 1
		"  while (__VERIFIER_nondet_int() < 10) {",       // 2
		"    if (__VERIFIER_nondet_bool()) {",            // 3
		"      x = __VERIFIER_nondet_uchar() ? 1 : 2;",   // 4
		"    } else if (a && __VERIFIER_nondet_int()) {", // 5
		"      switch (__VERIFIER_nondet_long()) {",      // 6
		"      default: break;",                          // 7
		"      }",                                        // 8
		"    }",                                          // 9
		"  }",                                            // 10
		"}",                                              // 11
	)
	w := &witness.Witness{Branchings: []witness.Branching{
		branch(2, 3, "true"),
		branch(3, 5, "true"),
		branch(4, 37, "false"),
		branch(2, 3, "true"),
		branch(3, 5, "false"),
		branch(5, 12, "true"),
		branch(6, 7, "default"),
		branch(9, 5, "true"),
		branch(2, 3, "false"),
	}}
	res := mustInstrument(t, src, w, Options{})
	if res.NondetSites != 5 || res.InjectedSites != 3 {
		t.Errorf("NondetSites = %d, InjectedSites = %d, want 5 and 3", res.NondetSites, res.InjectedSites)
	}
	for _, want := range []string{
		"int __VERIFIER_nondet_value_injection_2_32(void) {\n  static const int values[] = { 9, 9, 10 };",
		"_Bool __VERIFIER_nondet_value_injection_3_32(void) {\n  static const _Bool values[] = { 1, 0 };",
		"unsigned char __VERIFIER_nondet_value_injection_4_35(void) {\n  static const unsigned char values[] = { 0 };",
		"\n  while (__VERIFIER_nondet_value_injection_2_32() < 10) {\n",
		"\n    if (__VERIFIER_nondet_value_injection_3_32()) {\n",
		"\n      x = __VERIFIER_nondet_value_injection_4_35() ? 1 : 2;\n",
		"\n    } else if (a && __VERIFIER_nondet_int()) {\n",
		"\n      switch (__VERIFIER_nondet_long()) {\n",
	} {
		if !strings.Contains(res.Source, want) {
			t.Errorf("Source should contain %q.\ngot:\n%s", want, res.Source)
		}
	}
	wantNotes := []string{
		"branching at 5:12 (if, 1 waypoint) not matched: " + reasonShortCircuit,
		"branching at 6:7 (switch, 1 waypoint) not matched: waypoint value default does not determine an input value",
		"branching at 9:5 (true) not matched: no if, while, for, switch, do or '?' at the location",
	}
	if strings.Join(res.Notes, "\n") != strings.Join(wantNotes, "\n") {
		t.Errorf("notes:\n%s\nwant:\n%s", strings.Join(res.Notes, "\n"), strings.Join(wantNotes, "\n"))
	}
}

func TestFunctionReturnWinsOverBranching(t *testing.T) {
	src := lines("int main() {", "  while (__VERIFIER_nondet_int() > 0) {", "    n++;", "  }", "}")
	w := &witness.Witness{
		Points:     []witness.InjectionPoint{{Loc: witness.Location{Line: 2, Column: 32}, Value: "50"}, {Loc: witness.Location{Line: 2, Column: 32}, Value: "-50"}},
		Branchings: []witness.Branching{branch(2, 3, "true"), branch(2, 3, "false")},
	}
	res := mustInstrument(t, src, w, Options{})
	if res.InjectedSites != 1 || !strings.Contains(res.Source, "values[] = { 50, -50 };") {
		t.Errorf("only the function_return values may be injected (InjectedSites = %d).\ngot:\n%s", res.InjectedSites, res.Source)
	}
	wantNotes := []string{"branching at 2:3 (while, 2 waypoints) not used: the nondet call site at 2:32 has values from function_return waypoints"}
	if strings.Join(res.Notes, "\n") != strings.Join(wantNotes, "\n") {
		t.Errorf("notes:\n%s\nwant:\n%s", strings.Join(res.Notes, "\n"), strings.Join(wantNotes, "\n"))
	}
}

// Notes of all waypoint types are ordered by line and column.
func TestNotesAreOrderedByLocation(t *testing.T) {
	src := lines(
		"int main() {",                 // 1
		"  if (a && b) {",              // 2
		"    x = 5;",                   // 3
		"    y = x ? 1 : 2; return x;", // 4
		"  }",                          // 5
		"  while (__VERIFIER_nondet_pointer()) {", // 6
		"  }", // 7
		"}",   // 8
	)
	w := &witness.Witness{
		Assumptions: []witness.Assumption{assume(4, 20, "1"), assume(4, 5, "2"), assume(4, 0, "3")},
		Branchings:  []witness.Branching{branch(6, 3, "true"), branch(4, 11, "true"), branch(2, 3, "false"), branch(4, 0, "false")},
	}
	res := mustInstrument(t, src, w, Options{})
	want := []string{
		// No note for the if at 2:3: its condition has no nondet call.
		"assumption at 4 (x == 3) not matched: " + reasonNotPlainAssignment,
		"branching at 4 (false) not matched: " + reasonConditionalCondition,
		"assumption at 4:5 (x == 2) not matched: " + reasonNotPlainAssignment,
		"branching at 4:11 (true) not matched: " + reasonConditionalCondition,
		"assumption at 4:20 (x == 1) not matched: " + reasonNotPlainAssignment,
		`branching at 6:3 (while, 1 waypoint) not matched: nondet type "pointer" is not supported for branching waypoints`,
	}
	if strings.Join(res.Notes, "\n") != strings.Join(want, "\n") {
		t.Errorf("notes:\n%s\nwant:\n%s", strings.Join(res.Notes, "\n"), strings.Join(want, "\n"))
	}
	// Instrumenting again yields the same notes in the same order.
	again := mustInstrument(t, src, w, Options{})
	if strings.Join(again.Notes, "\n") != strings.Join(res.Notes, "\n") {
		t.Errorf("notes are not deterministic:\n%s\nvs.\n%s", strings.Join(res.Notes, "\n"), strings.Join(again.Notes, "\n"))
	}
}
