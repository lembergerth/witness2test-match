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
	"math/big"
	"regexp"
	"strings"

	"witness2test/witness"
)

// A branching waypoint states the value of the controlling expression of an
// if, loop, switch or conditional operator. If the controlling expression is
// a nondet call, its negation, or its comparison with an integer literal,
// the waypoint determines a value the call can return.
//
// Anything else is not matched. In particular, with && and || the witness
// does not say which operand decided the outcome, and no attempt is made to
// solve for the inputs of arbitrary expressions.
//
// All scanning is done on the masked program text, in which comments and
// literals are blanked. A controlling expression that contains a comment or
// a literal is not matched, see analyzeCondition.

// construct is a branching statement or conditional operator.
type construct struct {
	// kind is the keyword of the statement, or "?".
	kind string
	// pos is the offset of the keyword or of the '?'. It identifies the
	// construct.
	pos int
	// exprStart and exprEnd delimit the controlling expression.
	exprStart, exprEnd int
}

// branchingKeywords are the keywords a branching waypoint can be located at.
var branchingKeywords = []string{"if", "while", "for", "switch", "do"}

// Reasons why no construct is found for a branching waypoint.
const (
	reasonNoConstructAtLocation = "no if, while, for, switch, do or '?' at the location"
	reasonNoConstructOnLine     = "no if, while, for, switch, do or '?' on the line"
	reasonForClauses            = "the for statement does not have exactly three clauses"
	reasonDoForm                = "the do statement is not of the form do { ... } while (...)"
	reasonConditionalCondition  = "the condition of '?' is not a parenthesized expression or a nondet call on the line of the '?'"
	reasonConditionalContext    = "the condition of '?' may be part of a larger expression"
)

var nondetNameOnlyRegex = regexp.MustCompile(`^__VERIFIER_nondet_[a-zA-Z]+$`)

// foundConstruct is a memoized result of findConstruct.
type foundConstruct struct {
	construct construct
	reason    string
}

// findConstruct returns the construct a branching waypoint at loc refers to.
// If there is none, reason says why; it is empty on success.
//
// Results are memoized: a witness typically has many waypoints for the same
// loop, and finding the end of a do statement means scanning its body.
func (m *matcher) findConstruct(loc witness.Location) (c construct, reason string) {
	if found, ok := m.constructs[loc]; ok {
		return found.construct, found.reason
	}
	c, reason = m.scanConstruct(loc)
	m.constructs[loc] = foundConstruct{construct: c, reason: reason}
	return c, reason
}

func (m *matcher) scanConstruct(loc witness.Location) (c construct, reason string) {
	src := m.src
	if loc.Line < 1 || loc.Line > src.lineCount() {
		return construct{}, fmt.Sprintf("line %d does not exist", loc.Line)
	}
	text := src.maskedLine(loc.Line)
	kind, column0 := "", -1
	if loc.Column == 0 {
		// The first keyword on the line, or else the first '?'.
		for _, keyword := range branchingKeywords {
			for i := 0; i < len(text) && (column0 < 0 || i < column0); i++ {
				if isWordAt(text, i, keyword) {
					kind, column0 = keyword, i
					break
				}
			}
		}
		if column0 < 0 {
			kind, column0 = "?", strings.IndexByte(text, '?')
		}
		if column0 < 0 {
			return construct{}, reasonNoConstructOnLine
		}
	} else {
		column0 = loc.Column - 1
		for _, keyword := range branchingKeywords {
			if isWordAt(text, column0, keyword) {
				kind = keyword
			}
		}
		if kind == "" && column0 >= 0 && column0 < len(text) && text[column0] == '?' {
			kind = "?"
		}
		if kind == "" {
			return construct{}, reasonNoConstructAtLocation
		}
	}

	pos := src.lineStart(loc.Line) + column0
	c = construct{kind: kind, pos: pos}
	masked := src.masked
	switch kind {
	case "if", "while", "switch", "for":
		open, closing, ok := parenthesesAfter(masked, pos+len(kind))
		if !ok {
			return construct{}, "the controlling expression is not enclosed in parentheses on the line of the " + kind
		}
		c.exprStart, c.exprEnd = open+1, closing
		if kind == "for" {
			clauses := topLevelSemicolons(masked, open+1, closing)
			if len(clauses) != 2 {
				return construct{}, reasonForClauses
			}
			c.exprStart, c.exprEnd = clauses[0]+1, clauses[1]
		}
	case "do":
		open := skipSpace(masked, pos+len(kind))
		if open >= len(masked) || masked[open] != '{' {
			return construct{}, reasonDoForm
		}
		closing := matchingBrace(masked, open)
		if closing < 0 {
			return construct{}, reasonDoForm
		}
		while := skipSpace(masked, closing+1)
		if !isWordAt(masked, while, "while") {
			return construct{}, reasonDoForm
		}
		open, closing, ok := parenthesesAfter(masked, while+len("while"))
		if !ok {
			return construct{}, reasonDoForm
		}
		c.exprStart, c.exprEnd = open+1, closing
	case "?":
		c.exprStart, c.exprEnd, reason = conditionalCondition(masked, pos)
		if reason != "" {
			return construct{}, reason
		}
	}
	return c, ""
}

// parenthesesAfter expects, after optional whitespace on the same line, a
// '(' at offset pos and returns its offset and the offset of its matching
// ')' on the same line.
func parenthesesAfter(masked string, pos int) (open, closing int, ok bool) {
	open = skipLineSpace(masked, pos)
	if open >= len(masked) || masked[open] != '(' {
		return 0, 0, false
	}
	closing = matchingClose(masked, open)
	return open, closing, closing >= 0
}

// topLevelSemicolons returns the offsets of the semicolons in [start, end)
// that are not nested in parentheses, brackets or braces.
func topLevelSemicolons(masked string, start, end int) []int {
	var offsets []int
	depth := 0
	for i := start; i < end; i++ {
		switch masked[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case ';':
			if depth == 0 {
				offsets = append(offsets, i)
			}
		}
	}
	return offsets
}

// conditionalCondition determines the first operand of the conditional
// operator whose '?' is at offset question.
//
// The operand must end in ')' directly before the '?'. It is the nondet call
// that the parenthesis belongs to, or else the parenthesized expression. To
// make sure that this is the whole operand and not the end of a larger
// expression like "a + (b)", the operand must follow, on its line, one of
// ( , ; { } : ?, the keyword return, or an assignment. An operand that starts
// its line is not matched: the expression may continue from the previous
// line, as in "a +\n (b) ? 1 : 2".
func conditionalCondition(masked string, question int) (start, end int, reason string) {
	closing := skipLineSpaceBackward(masked, question-1)
	if closing < 0 || masked[closing] != ')' {
		return 0, 0, reasonConditionalCondition
	}
	open := matchingOpen(masked, closing)
	if open < 0 {
		return 0, 0, reasonConditionalCondition
	}
	start, end = open, closing+1
	if word, wordStart := wordBefore(masked, open); nondetNameOnlyRegex.MatchString(word) {
		start = wordStart
	} else if word != "" && word != "return" {
		// A call of another function, sizeof, or not an expression at all.
		return 0, 0, reasonConditionalCondition
	}

	before := skipLineSpaceBackward(masked, start-1)
	if before < 0 {
		return 0, 0, reasonConditionalContext
	}
	switch c := masked[before]; {
	case strings.IndexByte("(,;{}:?", c) >= 0:
		return start, end, ""
	case c == '=':
		// Not the second character of ==, !=, <= or >=.
		if before == 0 || strings.IndexByte("=!<>", masked[before-1]) < 0 {
			return start, end, ""
		}
	case isIdentChar(c):
		if word, _ := wordBefore(masked, before+1); word == "return" {
			return start, end, ""
		}
	}
	return 0, 0, reasonConditionalContext
}

// wordBefore returns the identifier-like word that ends before offset pos,
// ignoring whitespace within the line in between, and the offset of its
// first character. The word is empty if there is none.
func wordBefore(masked string, pos int) (word string, start int) {
	end := skipLineSpaceBackward(masked, pos-1) + 1
	start = end
	for start > 0 && isIdentChar(masked[start-1]) {
		start--
	}
	return masked[start:end], start
}

// conditionForm is the shape of a controlling expression we can solve.
type conditionForm int

const (
	// formCall is __VERIFIER_nondet_T().
	formCall conditionForm = iota + 1
	// formNegatedCall is !__VERIFIER_nondet_T().
	formNegatedCall
	// formComparison is __VERIFIER_nondet_T() <op> <integer literal>.
	formComparison
)

// condition is a controlling expression that consists of a single nondet
// call in one of the supported forms.
type condition struct {
	form     conditionForm
	typeName string // short name of the nondet function, e.g. "uint"
	// callStart and callEnd delimit the nondet call.
	callStart, callEnd int
	// op and constant are set for formComparison. The comparison is
	// normalised to "call op constant".
	op       string
	constant *big.Int
}

const (
	conditionCallPattern    = `(__VERIFIER_nondet_([a-zA-Z]+)\s*\(\s*(?:void\s*)?\))`
	conditionOpPattern      = `(==|!=|<=|>=|<|>)`
	conditionLiteralPattern = `(-?(?:0|[1-9][0-9]*))`
)

var (
	conditionCallRegex        = regexp.MustCompile(`^` + conditionCallPattern + `$`)
	conditionNegatedCallRegex = regexp.MustCompile(`^!\s*` + conditionCallPattern + `$`)
	conditionCallFirstRegex   = regexp.MustCompile(`^` + conditionCallPattern + `\s*` + conditionOpPattern + `\s*` + conditionLiteralPattern + `$`)
	conditionCallLastRegex    = regexp.MustCompile(`^` + conditionLiteralPattern + `\s*` + conditionOpPattern + `\s*` + conditionCallPattern + `$`)
)

// mirroredOperator maps the operator of "constant op call" to the operator
// of the equivalent "call op constant".
var mirroredOperator = map[string]string{
	"==": "==", "!=": "!=", "<": ">", "<=": ">=", ">": "<", ">=": "<=",
}

const (
	reasonShortCircuit         = "the controlling expression contains && or ||, so the witness does not say which operand decided the outcome"
	reasonUnsupportedCondition = "the controlling expression is not a nondet call, a negated nondet call, or a comparison of a nondet call with a decimal integer literal"
	reasonConditionNotOnlyCode = "the controlling expression contains a comment, a string literal or a character literal"
)

// analyzeCondition recognizes the controlling expression at the offsets
// [start, end) of src. Whitespace and parentheses around the whole expression
// are ignored; apart from that, the expression must be exactly one of the
// supported forms.
//
// The forms are recognized in the masked text. An expression that contains a
// comment or a string or character literal is therefore not matched at all:
// with the literal blanked, "__VERIFIER_nondet_int() == 'a'-96" would read
// as a comparison with -96.
func analyzeCondition(src *sourceText, start, end int) (c condition, reason string) {
	if !src.isCode(start, end) {
		return condition{}, reasonConditionNotOnlyCode
	}
	masked := src.masked
	failure := reasonUnsupportedCondition
	if expr := masked[start:end]; strings.Contains(expr, "&&") || strings.Contains(expr, "||") {
		failure = reasonShortCircuit
	}
	for {
		for start < end && (isLineSpace(masked[start]) || masked[start] == '\n') {
			start++
		}
		for end > start && (isLineSpace(masked[end-1]) || masked[end-1] == '\n') {
			end--
		}
		if end-start < 2 || masked[start] != '(' || matchingClose(masked[:end], start) != end-1 {
			break
		}
		start, end = start+1, end-1
	}
	expr := masked[start:end]

	// group returns the text of a capture group and its offset in masked.
	var groups []int
	group := func(n int) (string, int) {
		return expr[groups[2*n]:groups[2*n+1]], start + groups[2*n]
	}
	setCall := func(callGroup int) {
		call, offset := group(callGroup)
		c.callStart, c.callEnd = offset, offset+len(call)
		c.typeName, _ = group(callGroup + 1)
	}
	setComparison := func(op string, literalGroup int) bool {
		literal, _ := group(literalGroup)
		constant, ok := new(big.Int).SetString(literal, 10)
		c.form, c.op, c.constant = formComparison, op, constant
		return ok
	}

	if groups = conditionCallRegex.FindStringSubmatchIndex(expr); groups != nil {
		c.form = formCall
		setCall(1)
		return c, ""
	}
	if groups = conditionNegatedCallRegex.FindStringSubmatchIndex(expr); groups != nil {
		c.form = formNegatedCall
		setCall(1)
		return c, ""
	}
	if groups = conditionCallFirstRegex.FindStringSubmatchIndex(expr); groups != nil {
		setCall(1)
		op, _ := group(3)
		if setComparison(op, 4) {
			return c, ""
		}
	}
	if groups = conditionCallLastRegex.FindStringSubmatchIndex(expr); groups != nil {
		setCall(3)
		op, _ := group(2)
		if setComparison(mirroredOperator[op], 1) {
			return c, ""
		}
	}
	return condition{}, failure
}

// intRange is the inclusive range of an integer type.
type intRange struct {
	lo, hi *big.Int
}

func (r intRange) contains(v *big.Int) bool {
	return v.Cmp(r.lo) >= 0 && v.Cmp(r.hi) <= 0
}

func signedRange(bits uint) intRange {
	limit := new(big.Int).Lsh(big.NewInt(1), bits-1)
	return intRange{lo: new(big.Int).Neg(limit), hi: new(big.Int).Sub(limit, big.NewInt(1))}
}

func unsignedRange(bits uint) intRange {
	limit := new(big.Int).Lsh(big.NewInt(1), bits)
	return intRange{lo: big.NewInt(0), hi: new(big.Int).Sub(limit, big.NewInt(1))}
}

// integerRange returns the range of the type that the nondet function with
// the given short name returns. ok is false for all names that are not
// listed here, including the non-integer types.
func integerRange(typeName string, model dataModel) (r intRange, ok bool) {
	longBits := uint(64)
	if model == modelILP32 {
		longBits = 32
	}
	switch typeName {
	case "char":
		return signedRange(8), true
	case "uchar", "unsigned_char", "u8":
		return unsignedRange(8), true
	case "short":
		return signedRange(16), true
	case "ushort", "u16":
		return unsignedRange(16), true
	case "int":
		return signedRange(32), true
	case "uint", "unsigned", "u32", "U32":
		return unsignedRange(32), true
	case "long":
		return signedRange(longBits), true
	case "ulong":
		return unsignedRange(longBits), true
	case "longlong":
		return signedRange(64), true
	case "ulonglong":
		return unsignedRange(64), true
	case "bool":
		return intRange{lo: big.NewInt(0), hi: big.NewInt(1)}, true
	}
	return intRange{}, false
}

var (
	maxInt32 = big.NewInt(1<<31 - 1)
	maxInt64 = new(big.Int).SetUint64(1<<63 - 1)
	minInt64 = new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(1), 63))
)

// formatCInteger renders v as a C constant expression of that value which
// compiles without warnings in both data models. v must be within the range
// of long long or unsigned long long.
func formatCInteger(v *big.Int) string {
	switch {
	case v.CmpAbs(maxInt32) <= 0:
		return v.String()
	case v.Cmp(maxInt64) > 0:
		return v.String() + "ULL"
	case v.Cmp(minInt64) == 0:
		// The literal 9223372036854775808 does not fit into long long.
		return "(-" + maxInt64.String() + "LL - 1)"
	}
	return v.String() + "LL"
}

// switchValueRegex is the shape of an integer literal as accepted by the
// witness package: group 1 is the sign, group 2 the digits with base prefix.
// The suffix is one of the integer suffixes of C. The witness package also
// bounds the length of the literal, and thereby the cost of parsing it.
var switchValueRegex = regexp.MustCompile(`^([+-]?)(0[xX][0-9a-fA-F]+|0[bB][01]+|0[0-7]*|[1-9][0-9]*)(?:[uU](?:l|L|ll|LL)?|(?:l|L|ll|LL)[uU]?)?$`)

// valueFor returns the C expression that the nondet call of the condition
// has to return so that a branching waypoint with the given value is passed.
// kind is the kind of the construct. If there is no such value, or we cannot
// tell, reason says why; it is empty on success.
func (c condition) valueFor(kind, waypointValue string, model dataModel) (value, reason string) {
	typeRange, isInteger := integerRange(c.typeName, model)
	if kind == "switch" {
		return c.switchValue(waypointValue, typeRange, isInteger)
	}

	var outcome bool
	switch waypointValue {
	case "true":
		outcome = true
	case "false":
		outcome = false
	default:
		return "", fmt.Sprintf("waypoint value %q is neither true nor false", waypointValue)
	}

	switch c.form {
	case formCall, formNegatedCall:
		// Only types for which 0 is false and 1 is true: not pointers, and
		// not types we do not know.
		if !isInteger && c.typeName != "float" && c.typeName != "double" {
			return "", fmt.Sprintf("nondet type %q is not supported for branching waypoints", c.typeName)
		}
		if outcome == (c.form == formCall) {
			return "1", ""
		}
		return "0", ""
	case formComparison:
		if !isInteger {
			return "", fmt.Sprintf("nondet type %q is not an integer type with known range", c.typeName)
		}
		if !typeRange.contains(c.constant) {
			return "", fmt.Sprintf("constant %s is outside the range of nondet type %q", c.constant, c.typeName)
		}
		needed := c.comparisonValue(outcome, typeRange)
		if needed == nil {
			return "", fmt.Sprintf("no value of nondet type %q makes the comparison %s %s %s",
				c.typeName, c.op, c.constant, waypointValue)
		}
		return formatCInteger(needed), ""
	}
	return "", reasonUnsupportedCondition
}

// comparisonValue returns a value v in typeRange for which "v op constant"
// has the given outcome, or nil if the chosen candidate is not in the range.
func (c condition) comparisonValue(outcome bool, typeRange intRange) *big.Int {
	one := big.NewInt(1)
	above := new(big.Int).Add(c.constant, one)
	below := new(big.Int).Sub(c.constant, one)
	// different is a value other than the constant.
	different := above
	if !typeRange.contains(different) {
		different = below
	}
	var whenTrue, whenFalse *big.Int
	switch c.op {
	case "==":
		whenTrue, whenFalse = c.constant, different
	case "!=":
		whenTrue, whenFalse = different, c.constant
	case "<":
		whenTrue, whenFalse = below, c.constant
	case "<=":
		whenTrue, whenFalse = c.constant, above
	case ">":
		whenTrue, whenFalse = above, c.constant
	case ">=":
		whenTrue, whenFalse = c.constant, below
	default:
		return nil
	}
	needed := whenFalse
	if outcome {
		needed = whenTrue
	}
	if !typeRange.contains(needed) {
		return nil
	}
	return needed
}

// switchValue returns the value for a branching waypoint of a switch: the
// integer literal of the waypoint, which the call has to return as it is.
func (c condition) switchValue(waypointValue string, typeRange intRange, isInteger bool) (value, reason string) {
	if c.form != formCall {
		return "", "the controlling expression of the switch is not a plain nondet call"
	}
	if !isInteger || c.typeName == "bool" {
		return "", fmt.Sprintf("nondet type %q is not an integer type with known range", c.typeName)
	}
	if waypointValue == "default" {
		return "", "waypoint value default does not determine an input value"
	}
	m := switchValueRegex.FindStringSubmatch(waypointValue)
	if m == nil {
		return "", fmt.Sprintf("waypoint value %q is not an integer literal", waypointValue)
	}
	// Base 0 selects the base by the prefix, like C does.
	literal, ok := new(big.Int).SetString(m[2], 0)
	if !ok {
		return "", fmt.Sprintf("waypoint value %q is not an integer literal", waypointValue)
	}
	if m[1] == "-" {
		literal.Neg(literal)
	}
	if !typeRange.contains(literal) {
		return "", fmt.Sprintf("waypoint value %s is outside the range of nondet type %q", waypointValue, c.typeName)
	}
	return waypointValue, ""
}
