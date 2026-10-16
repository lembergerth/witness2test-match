// This file is part of witness2test-match,
// a tool to turn SV-COMP violation witnesses (format v2) into executable tests.
// https://github.com/lembergerth/witness2test-match
//
// SPDX-FileCopyrightText: 2026 Thomas Lemberger <https://thomaslemberger.com>
//
// SPDX-License-Identifier: Apache-2.0

// Package witness parses SV-COMP violation witnesses in YAML format v2 and
// extracts the ordered sequence of nondeterministic input values implied by
// function_return waypoints.
package witness

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Location identifies a source position by 1-based line and column.
// The column is the column of the closing parenthesis of the call expression,
// matching the Symbiotic convention for function_return waypoints.
type Location struct {
	Line   int
	Column int
}

// InjectionPoint pairs a source location with a concrete C-literal value to
// return from the matching __VERIFIER_nondet_*() call.
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
var (
	intLiteralRegex   = regexp.MustCompile(`^[+-]?(0[xX][0-9a-fA-F]+|0[bB][01]+|0[0-7]*|[1-9][0-9]*)[uUlL]{0,3}$`)
	floatLiteralRegex = regexp.MustCompile(`^[+-]?(\d+\.\d*|\.\d+|\d+)([eE][+-]?\d+)?[fFlL]?$`)
	charLiteralRegex  = regexp.MustCompile(`^'(\\['"\\nrt0]|\\x[0-9a-fA-F]{1,2}|[^'\\])'$`)
	boolLiteralRegex  = regexp.MustCompile(`^(true|false)$`)
)

// isAllowedLiteral reports whether v is one of the permitted C-literal forms.
func isAllowedLiteral(v string) bool {
	return intLiteralRegex.MatchString(v) ||
		floatLiteralRegex.MatchString(v) ||
		charLiteralRegex.MatchString(v) ||
		boolLiteralRegex.MatchString(v)
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
	var doc []entry
	if uerr := yaml.Unmarshal(yamlBytes, &doc); uerr != nil {
		return nil, WaypointCounts{}, fmt.Errorf("failed to parse witness YAML: %w", uerr)
	}

	wantBase := filepath.Base(programBasename)

	for _, e := range doc {
		if e.EntryType != "violation_sequence" {
			continue
		}
		for _, seg := range e.Content {
			for _, wh := range seg.Segment {
				w := wh.Waypoint
				countWaypoint(&counts, w.Type)
				if w.Type != "function_return" {
					continue
				}
				if w.Action != "" && w.Action != "follow" {
					continue
				}
				if w.Constraint == nil {
					continue
				}
				m := shapeRegex.FindStringSubmatch(w.Constraint.Value)
				if m == nil {
					continue
				}
				literal := m[1]
				// Hard error, not skip: the literal will be embedded verbatim in
				// generated C, so anything outside the allowlist is a potential
				// injection vector and must abort before code generation.
				if !isAllowedLiteral(literal) {
					return nil, counts, fmt.Errorf(
						"witness constraint value %q at %s:%d:%d is not an allowed C literal (integer, float, char, or bool)",
						w.Constraint.Value, w.Location.FileName, w.Location.Line, w.Location.Column)
				}
				if filepath.Base(w.Location.FileName) != wantBase {
					continue
				}
				if w.Location.Line <= 0 || w.Location.Column <= 0 {
					return nil, counts, fmt.Errorf(
						"witness waypoint at %s has invalid 1-based location (line=%d, column=%d)",
						w.Location.FileName, w.Location.Line, w.Location.Column)
				}
				points = append(points, InjectionPoint{
					Loc:   Location{Line: w.Location.Line, Column: w.Location.Column},
					Value: literal,
				})
			}
		}
	}
	return points, counts, nil
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

type entry struct {
	EntryType string    `yaml:"entry_type"`
	Content   []segment `yaml:"content"`
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
