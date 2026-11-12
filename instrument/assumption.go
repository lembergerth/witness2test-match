// This file is part of witness2test-match,
// a tool to turn SV-COMP violation witnesses (format v2) into executable tests.
// https://github.com/lembergerth/witness2test-match
//
// SPDX-FileCopyrightText: 2026 Thomas Lemberger <https://thomaslemberger.com>
//
// SPDX-License-Identifier: Apache-2.0

package instrument

import (
	"fmt"
	"regexp"
	"strings"

	"witness2test/witness"
)

// An assumption waypoint "x == <literal>" is evaluated at the sequence point
// directly before the statement at its location. If the statement executed
// directly before that sequence point is "x = __VERIFIER_nondet_T();", the
// literal is the value the call has to return.
//
// Without a parser, "the statement executed directly before" is established
// by the following rules. All of them must hold, otherwise the assumption is
// not matched:
//
//	a. The text before the location on its line is whitespace only, and the
//	   assignment line is the nearest previous line that is neither blank
//	   nor a comment-only line; or the text before the location is the
//	   assignment itself.
//	b. The assignment is exactly "x = __VERIFIER_nondet_T();" or
//	   "<type> x = __VERIFIER_nondet_T();", with nothing else on its line.
//	c. The nearest line before the assignment line that is neither blank nor
//	   a comment-only line ends in ';', '{' or '}'. Hence the assignment is
//	   not the body of a braceless if, else or loop, and it is not labelled.
//	d. The statement at the location is not labelled: control could reach it
//	   by a jump instead of from the assignment.
//	e. The call of the assignment is a call site known to CollectNondetCalls.

// plainAssignmentRegex matches the assignment of rule (b). Group 1 is the
// type (empty or identifiers, each followed by whitespace), group 2 the
// variable, group 3 the call.
var plainAssignmentRegex = regexp.MustCompile(
	`^((?:[A-Za-z_][A-Za-z0-9_]*[ \t]+)*)([A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*(` + nondetCallPattern + `)[ \t]*;$`)

// labelRegex matches an identifier followed by a colon at the start of a
// statement. Whether the colon is the first half of "::" is checked by hand:
// the regexp package has no lookahead.
var labelRegex = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*\s*:`)

// statementKeywords are the keywords that can precede "x = ...;" without
// being part of a declaration of x: "else x = f();" has the shape
// "<type> x = f();", but the assignment is the body of the else.
var statementKeywords = map[string]bool{
	"break": true, "case": true, "continue": true, "default": true, "do": true,
	"else": true, "for": true, "goto": true, "if": true, "return": true,
	"sizeof": true, "switch": true, "while": true,
}

// Reasons why an assumption is not matched, as used in notes.
const (
	reasonNotStatementStart  = "location is not the first character of a statement"
	reasonLabelled           = "statement at the location is labelled"
	reasonNotPlainAssignment = "previous statement is not a plain assignment from a nondet call"
	reasonNotAfterStatement  = "the assignment does not directly follow a line ending in ';', '{' or '}'"
	reasonUnknownCallSite    = "the nondet call of the assignment is not a recognized call site"
)

// matchAssumption returns the call site whose return value the assumption
// determines. If the assumption is not matched, reason says why; it is empty
// on success.
func (m *matcher) matchAssumption(a witness.Assumption) (site NondetCallSite, reason string) {
	src := m.src
	line, column := a.Loc.Line, a.Loc.Column
	if line < 1 || line > src.lineCount() {
		return NondetCallSite{}, fmt.Sprintf("line %d does not exist", line)
	}
	text := src.line(line)
	if column == 0 {
		column = skipLineSpace(text, 0) + 1
	}
	if column < 1 || column > len(text) || isLineSpace(text[column-1]) || src.kinds[src.lineStart(line)+column-1] != kindCode {
		return NondetCallSite{}, reasonNotStatementStart
	}
	if startsWithLabel(src.maskedLine(line)[column-1:]) {
		return NondetCallSite{}, reasonLabelled
	}

	// Rule (a): find the assignment.
	assignmentLine := line
	assignment := text[:column-1]
	if strings.TrimSpace(assignment) == "" {
		assignmentLine = src.previousStatementLine(line)
		if assignmentLine == 0 {
			return NondetCallSite{}, reasonNotPlainAssignment
		}
		assignment = src.line(assignmentLine)
	}

	// Rule (b): the assignment and nothing else.
	start := skipLineSpace(assignment, 0)
	assignment = strings.TrimSpace(assignment)
	groups := plainAssignmentRegex.FindStringSubmatchIndex(assignment)
	if groups == nil {
		return NondetCallSite{}, reasonNotPlainAssignment
	}
	offset := src.lineStart(assignmentLine) + start
	if !src.isCode(offset, offset+len(assignment)) {
		return NondetCallSite{}, reasonNotPlainAssignment
	}
	for _, word := range strings.Fields(assignment[groups[2]:groups[3]]) {
		if statementKeywords[word] {
			return NondetCallSite{}, reasonNotPlainAssignment
		}
	}
	if variable := assignment[groups[4]:groups[5]]; variable != a.Variable {
		return NondetCallSite{}, fmt.Sprintf("previous statement assigns to %s, not to %s", variable, a.Variable)
	}

	// Rule (c): the assignment follows a complete statement or a brace.
	guardLine := src.previousStatementLine(assignmentLine)
	if guardLine == 0 || !src.endsStatementOrBlock(guardLine) {
		return NondetCallSite{}, reasonNotAfterStatement
	}

	// Rule (e).
	site, ok := m.siteAt(assignmentLine, start+groups[6], start+groups[7])
	if !ok {
		return NondetCallSite{}, reasonUnknownCallSite
	}
	return site, ""
}

// startsWithLabel implements rule (d) for the masked text of a statement.
func startsWithLabel(statement string) bool {
	if isWordAt(statement, 0, "case") || isWordAt(statement, 0, "default") {
		return true
	}
	label := labelRegex.FindString(statement)
	return label != "" && !strings.HasPrefix(statement[len(label):], ":")
}

// previousStatementLine returns the nearest line before the given line that
// is neither blank nor a comment-only line, or 0 if there is none.
func (s *sourceText) previousStatementLine(line int) int {
	for line--; line >= 1; line-- {
		if strings.TrimSpace(s.line(line)) != "" && !s.isCommentOnlyLine(line) {
			return line
		}
	}
	return 0
}

// isCommentOnlyLine reports whether the line consists of nothing but one //
// comment or one /* ... */ comment that starts and ends on this line.
// Lines that are part of a comment spanning several lines do not count.
func (s *sourceText) isCommentOnlyLine(line int) bool {
	start := s.lineStart(line)
	trimmed := strings.TrimSpace(s.line(line))
	if trimmed == "" {
		return false
	}
	first := start + skipLineSpace(s.line(line), 0)
	// A comment that was opened on an earlier line also covers the newline
	// before this line.
	continued := start > 0 && s.kinds[start-1] != kindCode
	switch s.kinds[first] {
	case kindLineComment:
		return !continued && strings.HasPrefix(trimmed, "//")
	case kindBlockComment:
		if continued || !strings.HasPrefix(trimmed, "/*") {
			return false
		}
		// The first "*/" closes the comment and must end the line.
		closing := strings.Index(trimmed[2:], "*/")
		return closing >= 0 && 2+closing+2 == len(trimmed)
	}
	return false
}

// endsStatementOrBlock implements rule (c) for one line: after removing
// trailing whitespace and a trailing // comment, the line ends in ';', '{'
// or '}'. Preprocessor directives never qualify.
func (s *sourceText) endsStatementOrBlock(line int) bool {
	start := s.lineStart(line)
	text := s.line(line)
	if strings.HasPrefix(strings.TrimSpace(s.maskedLine(line)), "#") {
		return false
	}
	end := len(text)
	for i := 0; i < len(text); i++ {
		if s.kinds[start+i] == kindLineComment {
			end = i
			break
		}
	}
	text = strings.TrimRight(text[:end], " \t\r\f\v")
	if text == "" {
		return false
	}
	last := len(text) - 1
	return s.kinds[start+last] == kindCode && strings.IndexByte(";{}", text[last]) >= 0
}
