// This file is part of witness2test-match,
// a tool to turn SV-COMP violation witnesses (format v2) into executable tests.
// https://github.com/lembergerth/witness2test-match
//
// SPDX-FileCopyrightText: 2026 Thomas Lemberger <https://thomaslemberger.com>
//
// SPDX-License-Identifier: Apache-2.0

// Package witness parses SV-COMP violation witnesses in YAML format v2 and
// extracts the waypoints that imply nondeterministic input values
// (function_return, assumption and branching waypoints) as well as the target
// waypoints and the specification the witness was produced for.
package witness

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Location identifies a source position by 1-based line and column.
// For function_return waypoints, the column is the column of the closing
// parenthesis of the call expression. For the other waypoint types, a column
// of 0 means that the witness does not specify a column.
type Location struct {
	Line   int
	Column int
}

// InjectionPoint pairs a source location with a concrete C-literal value to
// return from the matching __VERIFIER_nondet_*() call. The literals true and
// false of the witness are stored as 1 and 0.
type InjectionPoint struct {
	Loc   Location
	Value string
}

// WaypointCounts summarizes what was in the witness, for diagnostics when we
// cannot extract any injection points.
type WaypointCounts struct {
	FunctionReturn int
	Assumption     int
	Branching      int
	FunctionEnter  int
	Target         int
	Other          int
}

// shape captures the right-hand side of "\result == <expr>".
var shapeRegex = regexp.MustCompile(`^\s*\\?result\s*==\s*(.+?)\s*$`)

// C-literal allowlist regexes. The captured value from shapeRegex must match
// one of these. Anything else is rejected to prevent injection of arbitrary
// C code (e.g. function calls or statement terminators) into the generated
// source.
//
// The regexes accept only what a C compiler accepts as well:
//   - An integer has one of the suffixes of C: u, l or ll, or both in either
//     order ("lL" and "Ll" are not suffixes).
//   - A float has a fraction or an exponent. A bare digit sequence is an
//     integer and has to be a valid one: "08" and "1f" are neither.
//   - The character between the quotes of a character literal is a printable
//     ASCII character other than ' and \, or one of the listed escape
//     sequences. Control characters and bytes outside ASCII are not accepted.
var (
	intLiteralRegex   = regexp.MustCompile(`^[+-]?(0[xX][0-9a-fA-F]+|0[bB][01]+|0[0-7]*|[1-9][0-9]*)([uU](l|L|ll|LL)?|(l|L|ll|LL)[uU]?)?$`)
	floatLiteralRegex = regexp.MustCompile(`^[+-]?((\d+\.\d*|\.\d+)([eE][+-]?\d+)?|\d+[eE][+-]?\d+)[fFlL]?$`)
	charLiteralRegex  = regexp.MustCompile(`^'(\\['"\\nrt0]|\\x[0-9a-fA-F]{1,2}|[\x20-\x26\x28-\x5B\x5D-\x7E])'$`)
	boolLiteralRegex  = regexp.MustCompile(`^(true|false)$`)
)

// maxLiteralLength is the maximal length of a literal of the allowlist. No
// value of a C type needs more characters, and the bound limits the work
// that later stages spend on a value, such as parsing it as a big integer.
const maxLiteralLength = 64

// isAllowedLiteral reports whether v is one of the permitted C-literal forms
// and at most maxLiteralLength characters long.
func isAllowedLiteral(v string) bool {
	if len(v) > maxLiteralLength {
		return false
	}
	return intLiteralRegex.MatchString(v) ||
		floatLiteralRegex.MatchString(v) ||
		charLiteralRegex.MatchString(v) ||
		boolLiteralRegex.MatchString(v)
}

// cValue returns the text that is embedded in generated C for a literal of
// the allowlist. It is the literal itself, except for true and false: the
// generated code is compiled without <stdbool.h>, so they become 1 and 0.
func cValue(literal string) string {
	switch literal {
	case "true":
		return "1"
	case "false":
		return "0"
	}
	return literal
}

// Assumption is an assumption waypoint of the form "<variable> == <literal>".
// Loc is the first character of the statement before which the assumption
// holds. Loc.Column is 0 if the witness does not specify a column. Value is
// the literal; true and false are stored as 1 and 0.
type Assumption struct {
	Loc      Location
	Variable string
	Value    string
}

// Branching is a branching waypoint. Value is "true", "false", "default", or
// an integer literal of at most maxLiteralLength characters. Loc.Column is 0
// if the witness does not specify a column.
type Branching struct {
	Loc   Location
	Value string
}

// Witness is everything witness2test-match extracts from a violation witness.
type Witness struct {
	// Specification is metadata.task.specification of the first
	// violation_sequence entry, "" if absent.
	Specification string
	// DataModel is metadata.task.data_model of the first violation_sequence
	// entry, "" if absent.
	DataModel string
	// ViolationSequences is the number of entries with entry_type
	// violation_sequence in the document. It is 0 for a correctness witness
	// and for an empty document; ParseWitness does not treat that as an
	// error, the caller decides.
	ViolationSequences int
	// Points are the function_return waypoints, exactly as returned by Parse.
	Points []InjectionPoint
	// Assumptions, Branchings and Targets are in document order. The column
	// of their locations is 0 if the witness does not specify one.
	Assumptions []Assumption
	Branchings  []Branching
	Targets     []Location
	Counts      WaypointCounts
}

// Regexes for the two accepted shapes of an assumption, after one optional
// pair of outer parentheses was removed. The literal side is validated
// separately with isAllowedLiteral.
var (
	assumptionVariableFirstRegex = regexp.MustCompile(`(?s)^([A-Za-z_][A-Za-z0-9_]*)\s*==\s*(.+)$`)
	assumptionLiteralFirstRegex  = regexp.MustCompile(`(?s)^(.+?)\s*==\s*([A-Za-z_][A-Za-z0-9_]*)$`)
)

// ParseWitness extracts everything witness2test-match can interpret from a v2
// violation witness. Only waypoints with action "follow" (or no action) whose
// location is in the file programBasename are extracted.
//
// A function_return waypoint with a constraint value outside the literal
// allowlist, or with an invalid location, is an error (see Parse). Assumption,
// branching and target waypoints that cannot be interpreted are skipped
// silently; they are still reflected in Counts.
//
// A document without a violation_sequence entry is not an error: the result
// has ViolationSequences == 0 and the caller decides what that means.
func ParseWitness(yamlBytes []byte, programBasename string) (*Witness, error) {
	w, err := parseWitness(yamlBytes, programBasename)
	if err != nil {
		return nil, err
	}
	return &w, nil
}

// Parse extracts InjectionPoints from a v2 violation witness in document order
// and returns a per-type waypoint summary alongside, so callers can distinguish
// "no points we can interpret" from "witness rejected".
//
// An allowlist-violating constraint value is treated as an error rather than a
// silent skip: a witness file is operator-controlled but its contents are not,
// and a non-literal RHS in a constraint we then embed verbatim in generated C
// would be a code-injection vector. See isAllowedLiteral.
func Parse(yamlBytes []byte, programBasename string) (points []InjectionPoint, counts WaypointCounts, err error) {
	w, err := parseWitness(yamlBytes, programBasename)
	if err != nil {
		return nil, w.Counts, err
	}
	return w.Points, w.Counts, nil
}

// parseWitness implements ParseWitness. On error, the returned Witness only
// carries the waypoint counts up to the failing waypoint.
func parseWitness(yamlBytes []byte, programBasename string) (Witness, error) {
	var doc []entry
	if uerr := yaml.Unmarshal(yamlBytes, &doc); uerr != nil {
		return Witness{}, &yamlError{err: uerr}
	}

	wantBase := filepath.Base(programBasename)

	var result Witness
	for _, e := range doc {
		if e.EntryType != "violation_sequence" {
			continue
		}
		result.ViolationSequences++
		if result.ViolationSequences == 1 {
			result.Specification = e.Metadata.Task.Specification
			result.DataModel = e.Metadata.Task.DataModel
		}
		for _, seg := range e.Content {
			for _, wh := range seg.Segment {
				w := wh.Waypoint
				countWaypoint(&result.Counts, w.Type)
				if w.Action != "" && w.Action != "follow" {
					continue
				}
				if w.Type == "function_return" {
					point, ok, err := functionReturnPoint(w, wantBase)
					if err != nil {
						return Witness{Counts: result.Counts}, err
					}
					if ok {
						result.Points = append(result.Points, point)
					}
					continue
				}
				// Unlike function_return, the column of the remaining waypoint
				// types is optional: 0 means that the witness does not specify it.
				if filepath.Base(w.Location.FileName) != wantBase || w.Location.Line <= 0 || w.Location.Column < 0 {
					continue
				}
				loc := Location{Line: w.Location.Line, Column: w.Location.Column}
				switch w.Type {
				case "assumption":
					if w.Constraint == nil {
						continue
					}
					if variable, value, ok := parseAssumption(w.Constraint.Value); ok {
						result.Assumptions = append(result.Assumptions, Assumption{Loc: loc, Variable: variable, Value: value})
					}
				case "branching":
					if w.Constraint == nil {
						continue
					}
					if value, ok := parseBranchingValue(w.Constraint.Value); ok {
						result.Branchings = append(result.Branchings, Branching{Loc: loc, Value: value})
					}
				case "target":
					result.Targets = append(result.Targets, loc)
				}
			}
		}
	}
	return result, nil
}

// yamlError is a failure of the YAML decoder. The decoder quotes the scalar
// it cannot convert in its message, and that scalar is content of the
// witness. Like the file names and constraint values in the other messages
// of this package, it must not be able to add lines or terminal escape
// sequences to the message: characters that are not printable are escaped.
type yamlError struct {
	err error
}

func (e *yamlError) Error() string {
	const prefix = "failed to parse witness YAML: "
	var typeErr *yaml.TypeError
	if errors.As(e.err, &typeErr) {
		// The decoder joins the individual errors with line breaks.
		return prefix + "yaml: unmarshal errors: " + printable(strings.Join(typeErr.Errors, "; "))
	}
	return prefix + printable(e.err.Error())
}

func (e *yamlError) Unwrap() error {
	return e.err
}

// printable returns s with every character that is not printable replaced by
// its Go escape sequence.
func printable(s string) string {
	var b strings.Builder
	for _, r := range s {
		if strconv.IsPrint(r) {
			b.WriteRune(r)
			continue
		}
		quoted := strconv.QuoteRune(r)
		b.WriteString(quoted[1 : len(quoted)-1])
	}
	return b.String()
}

// functionReturnPoint turns a followed function_return waypoint into an
// InjectionPoint. ok is false if the waypoint carries no value for the program.
func functionReturnPoint(w waypoint, wantBase string) (point InjectionPoint, ok bool, err error) {
	if w.Constraint == nil {
		return InjectionPoint{}, false, nil
	}
	m := shapeRegex.FindStringSubmatch(w.Constraint.Value)
	if m == nil {
		return InjectionPoint{}, false, nil
	}
	literal := m[1]
	// Hard error, not skip: the literal will be embedded verbatim in
	// generated C, so anything outside the allowlist is a potential
	// injection vector and must abort before code generation.
	//
	// The constraint value and the file name are content of the witness.
	// They are printed with %q so that they cannot add lines or terminal
	// escape sequences to the message.
	if !isAllowedLiteral(literal) {
		return InjectionPoint{}, false, fmt.Errorf(
			"witness constraint value %q at %q:%d:%d is not an allowed C literal (integer, float, char, or bool of at most %d characters)",
			w.Constraint.Value, w.Location.FileName, w.Location.Line, w.Location.Column, maxLiteralLength)
	}
	if filepath.Base(w.Location.FileName) != wantBase {
		return InjectionPoint{}, false, nil
	}
	if w.Location.Line <= 0 || w.Location.Column <= 0 {
		return InjectionPoint{}, false, fmt.Errorf(
			"witness waypoint at %q has invalid 1-based location (line=%d, column=%d)",
			w.Location.FileName, w.Location.Line, w.Location.Column)
	}
	return InjectionPoint{
		Loc:   Location{Line: w.Location.Line, Column: w.Location.Column},
		Value: cValue(literal),
	}, true, nil
}

// parseAssumption accepts exactly "<identifier> == <literal>" and
// "<literal> == <identifier>", optionally wrapped in one pair of parentheses.
// The literal must pass isAllowedLiteral because it is later embedded in
// generated C. Anything else is not an assumption we can turn into an input
// value, and ok is false. The returned literal is the text to embed, see
// cValue.
func parseAssumption(constraintValue string) (variable, literal string, ok bool) {
	expr := strings.TrimSpace(constraintValue)
	if strings.HasPrefix(expr, "(") && strings.HasSuffix(expr, ")") {
		expr = strings.TrimSpace(expr[1 : len(expr)-1])
	}
	// true and false are literals of the allowlist, never variables.
	if m := assumptionVariableFirstRegex.FindStringSubmatch(expr); m != nil &&
		isAllowedLiteral(m[2]) && !boolLiteralRegex.MatchString(m[1]) {
		return m[1], cValue(m[2]), true
	}
	if m := assumptionLiteralFirstRegex.FindStringSubmatch(expr); m != nil &&
		isAllowedLiteral(m[1]) && !boolLiteralRegex.MatchString(m[2]) {
		return m[2], cValue(m[1]), true
	}
	return "", "", false
}

// parseBranchingValue accepts the constraint values of branching waypoints:
// true and false for if, loops and the conditional operator, and an integer
// literal of at most maxLiteralLength characters or default for switch.
// true and false are outcomes here, not values that are embedded in C.
func parseBranchingValue(constraintValue string) (value string, ok bool) {
	value = strings.TrimSpace(constraintValue)
	switch {
	case value == "true", value == "false", value == "default":
		return value, true
	case len(value) <= maxLiteralLength && intLiteralRegex.MatchString(value):
		return value, true
	}
	return "", false
}

// GroupByLocation collects values per location, preserving the document order
// in each bucket.
func GroupByLocation(points []InjectionPoint) map[Location][]string {
	if len(points) == 0 {
		return nil
	}
	m := make(map[Location][]string, len(points))
	for _, p := range points {
		m[p.Loc] = append(m[p.Loc], p.Value)
	}
	return m
}

func countWaypoint(c *WaypointCounts, typ string) {
	switch typ {
	case "function_return":
		c.FunctionReturn++
	case "assumption":
		c.Assumption++
	case "branching":
		c.Branching++
	case "function_enter":
		c.FunctionEnter++
	case "target":
		c.Target++
	default:
		c.Other++
	}
}

// Summary returns a human-readable summary string for diagnostics.
func (c WaypointCounts) Summary() string {
	var parts []string
	if c.FunctionReturn > 0 {
		parts = append(parts, fmt.Sprintf("function_return=%d", c.FunctionReturn))
	}
	if c.Assumption > 0 {
		parts = append(parts, fmt.Sprintf("assumption=%d", c.Assumption))
	}
	if c.Branching > 0 {
		parts = append(parts, fmt.Sprintf("branching=%d", c.Branching))
	}
	if c.FunctionEnter > 0 {
		parts = append(parts, fmt.Sprintf("function_enter=%d", c.FunctionEnter))
	}
	if c.Target > 0 {
		parts = append(parts, fmt.Sprintf("target=%d", c.Target))
	}
	if c.Other > 0 {
		parts = append(parts, fmt.Sprintf("other=%d", c.Other))
	}
	if len(parts) == 0 {
		return "no waypoints"
	}
	return strings.Join(parts, ", ")
}

// The YAML types only declare the keys we read. All other keys, such as
// thread_id (an integer or the string "any"), are ignored by the decoder.
type entry struct {
	EntryType string    `yaml:"entry_type"`
	Metadata  metadata  `yaml:"metadata"`
	Content   []segment `yaml:"content"`
}

type metadata struct {
	Task task `yaml:"task"`
}

type task struct {
	Specification string `yaml:"specification"`
	DataModel     string `yaml:"data_model"`
}

type segment struct {
	Segment []waypointHolder `yaml:"segment"`
}

type waypointHolder struct {
	Waypoint waypoint `yaml:"waypoint"`
}

type waypoint struct {
	Type       string      `yaml:"type"`
	Action     string      `yaml:"action"`
	Location   location    `yaml:"location"`
	Constraint *constraint `yaml:"constraint,omitempty"`
}

type location struct {
	FileName string `yaml:"file_name"`
	Line     int    `yaml:"line"`
	Column   int    `yaml:"column"`
	Function string `yaml:"function,omitempty"`
}

type constraint struct {
	Value  string `yaml:"value"`
	Format string `yaml:"format"`
}
