// This file is part of witness2test-match,
// a tool to turn SV-COMP violation witnesses (format v2) into executable tests.
// https://github.com/lembergerth/witness2test-match
//
// SPDX-FileCopyrightText: 2026 Thomas Lemberger <https://thomaslemberger.com>
//
// SPDX-License-Identifier: Apache-2.0

package witness

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// witnessYAML builds a single violation_sequence entry around the given
// waypoints. Each waypoint is the YAML flow mapping of one waypoint, e.g.
// `{ type: target, action: follow, location: { file_name: p.c, line: 3 } }`.
func witnessYAML(metadata string, waypoints ...string) []byte {
	var b strings.Builder
	b.WriteString("- entry_type: violation_sequence\n")
	if metadata != "" {
		b.WriteString("  metadata:\n")
		for _, line := range strings.Split(strings.TrimRight(metadata, "\n"), "\n") {
			b.WriteString("    " + line + "\n")
		}
	}
	b.WriteString("  content:\n")
	for _, wp := range waypoints {
		b.WriteString("  - segment:\n    - waypoint: " + wp + "\n")
	}
	return []byte(b.String())
}

func waypointYAML(typ, action, constraint, location string) string {
	parts := []string{"type: " + typ}
	if action != "" {
		parts = append(parts, "action: "+action)
	}
	if constraint != "" {
		parts = append(parts, "constraint: { value: "+constraint+" }")
	}
	parts = append(parts, "location: { "+location+" }")
	return "{ " + strings.Join(parts, ", ") + " }"
}

func loc(line, column int) string {
	return fmt.Sprintf("file_name: p.c, line: %d, column: %d", line, column)
}

func TestParseWitnessMetadata(t *testing.T) {
	target := waypointYAML("target", "follow", "", loc(3, 1))
	tests := []struct {
		name          string
		yaml          []byte
		specification string
		dataModel     string
	}{
		{
			name: "specification and data model",
			yaml: witnessYAML("task:\n  specification: \"G ! call(reach_error())\"\n  data_model: ILP32\n  language: C",
				target),
			specification: "G ! call(reach_error())",
			dataModel:     "ILP32",
		},
		{
			name:          "no metadata",
			yaml:          witnessYAML("", target),
			specification: "",
			dataModel:     "",
		},
		{
			name:          "metadata without task",
			yaml:          witnessYAML("format_version: \"2.1\"", target),
			specification: "",
			dataModel:     "",
		},
		{
			name: "first violation_sequence entry wins",
			yaml: []byte("- entry_type: invariant_set\n" +
				"  metadata: { task: { specification: \"ignored\", data_model: \"ignored\" } }\n" +
				"- entry_type: violation_sequence\n" +
				"  metadata: { task: { specification: \"first\", data_model: \"LP64\" } }\n" +
				"  content: []\n" +
				"- entry_type: violation_sequence\n" +
				"  metadata: { task: { specification: \"second\", data_model: \"ILP32\" } }\n" +
				"  content: []\n"),
			specification: "first",
			dataModel:     "LP64",
		},
		{
			name: "absent values of the first entry are not taken from a later entry",
			yaml: []byte("- entry_type: violation_sequence\n" +
				"  content: []\n" +
				"- entry_type: violation_sequence\n" +
				"  metadata: { task: { specification: \"second\", data_model: \"ILP32\" } }\n" +
				"  content: []\n"),
			specification: "",
			dataModel:     "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w, err := ParseWitness(tt.yaml, "p.c")
			if err != nil {
				t.Fatalf("ParseWitness: %v", err)
			}
			if w.Specification != tt.specification {
				t.Errorf("Specification = %q, want %q", w.Specification, tt.specification)
			}
			if w.DataModel != tt.dataModel {
				t.Errorf("DataModel = %q, want %q", w.DataModel, tt.dataModel)
			}
		})
	}
}

func TestParseWitnessAssumptions(t *testing.T) {
	tests := []struct {
		name     string
		waypoint string
		want     []Assumption
	}{
		{
			name:     "identifier == literal",
			waypoint: waypointYAML("assumption", "follow", `"x == 5"`, loc(12, 3)),
			want:     []Assumption{{Loc: Location{12, 3}, Variable: "x", Value: "5"}},
		},
		{
			name:     "literal == identifier",
			waypoint: waypointYAML("assumption", "follow", `"-7 == _tmp1"`, loc(12, 3)),
			want:     []Assumption{{Loc: Location{12, 3}, Variable: "_tmp1", Value: "-7"}},
		},
		{
			name:     "one pair of outer parentheses",
			waypoint: waypointYAML("assumption", "follow", `"(x == 5)"`, loc(12, 3)),
			want:     []Assumption{{Loc: Location{12, 3}, Variable: "x", Value: "5"}},
		},
		{
			name:     "arbitrary whitespace",
			waypoint: waypointYAML("assumption", "follow", `"  ( \t x==0x1F  )  "`, loc(12, 3)),
			want:     []Assumption{{Loc: Location{12, 3}, Variable: "x", Value: "0x1F"}},
		},
		{
			name:     "float literal",
			waypoint: waypointYAML("assumption", "follow", `"f == 1.5e-3f"`, loc(12, 3)),
			want:     []Assumption{{Loc: Location{12, 3}, Variable: "f", Value: "1.5e-3f"}},
		},
		{
			name:     "char literal",
			waypoint: waypointYAML("assumption", "follow", `"c == 'a'"`, loc(12, 3)),
			want:     []Assumption{{Loc: Location{12, 3}, Variable: "c", Value: "'a'"}},
		},
		{
			name:     "char literal that is a space",
			waypoint: waypointYAML("assumption", "follow", `"' ' == c"`, loc(12, 3)),
			want:     []Assumption{{Loc: Location{12, 3}, Variable: "c", Value: "' '"}},
		},
		{
			name:     "bool literal",
			waypoint: waypointYAML("assumption", "follow", `"b == true"`, loc(12, 3)),
			want:     []Assumption{{Loc: Location{12, 3}, Variable: "b", Value: "1"}},
		},
		{
			name:     "unquoted YAML scalar",
			waypoint: waypointYAML("assumption", "follow", `x == 5`, loc(12, 3)),
			want:     []Assumption{{Loc: Location{12, 3}, Variable: "x", Value: "5"}},
		},
		{
			name:     "column absent means unspecified",
			waypoint: waypointYAML("assumption", "follow", `"x == 5"`, "file_name: p.c, line: 12"),
			want:     []Assumption{{Loc: Location{12, 0}, Variable: "x", Value: "5"}},
		},
		{
			name:     "column zero means unspecified",
			waypoint: waypointYAML("assumption", "follow", `"x == 5"`, loc(12, 0)),
			want:     []Assumption{{Loc: Location{12, 0}, Variable: "x", Value: "5"}},
		},
		{
			name:     "empty action counts as follow",
			waypoint: waypointYAML("assumption", "", `"x == 5"`, loc(12, 3)),
			want:     []Assumption{{Loc: Location{12, 3}, Variable: "x", Value: "5"}},
		},
		{
			name:     "path in file_name is compared by basename",
			waypoint: waypointYAML("assumption", "follow", `"x == 5"`, "file_name: some/dir/p.c, line: 12, column: 3"),
			want:     []Assumption{{Loc: Location{12, 3}, Variable: "x", Value: "5"}},
		},
		// Everything below is silently skipped.
		{name: "avoid action", waypoint: waypointYAML("assumption", "avoid", `"x == 5"`, loc(12, 3))},
		{name: "cycle action", waypoint: waypointYAML("assumption", "cycle", `"x == 5"`, loc(12, 3))},
		{name: "other file", waypoint: waypointYAML("assumption", "follow", `"x == 5"`, "file_name: q.c, line: 12, column: 3")},
		{name: "no constraint", waypoint: waypointYAML("assumption", "follow", "", loc(12, 3))},
		{name: "line zero", waypoint: waypointYAML("assumption", "follow", `"x == 5"`, loc(0, 3))},
		{name: "line absent", waypoint: waypointYAML("assumption", "follow", `"x == 5"`, "file_name: p.c, column: 3")},
		{name: "negative line", waypoint: waypointYAML("assumption", "follow", `"x == 5"`, loc(-1, 3))},
		{name: "negative column", waypoint: waypointYAML("assumption", "follow", `"x == 5"`, loc(12, -1))},
		{name: "two pairs of outer parentheses", waypoint: waypointYAML("assumption", "follow", `"((x == 5))"`, loc(12, 3))},
		{name: "unbalanced parenthesis", waypoint: waypointYAML("assumption", "follow", `"(x == 5"`, loc(12, 3))},
		{name: "parenthesized identifier", waypoint: waypointYAML("assumption", "follow", `"(x) == 5"`, loc(12, 3))},
		{name: "parenthesized literal", waypoint: waypointYAML("assumption", "follow", `"x == (5)"`, loc(12, 3))},
		{name: "inequality", waypoint: waypointYAML("assumption", "follow", `"x != 5"`, loc(12, 3))},
		{name: "less than", waypoint: waypointYAML("assumption", "follow", `"x <= 5"`, loc(12, 3))},
		{name: "single equals sign", waypoint: waypointYAML("assumption", "follow", `"x = 5"`, loc(12, 3))},
		{name: "conjunction", waypoint: waypointYAML("assumption", "follow", `"x == 5 && y == 6"`, loc(12, 3))},
		{name: "chained equality", waypoint: waypointYAML("assumption", "follow", `"x == 5 == 1"`, loc(12, 3))},
		{name: "two identifiers", waypoint: waypointYAML("assumption", "follow", `"x == y"`, loc(12, 3))},
		{name: "two literals", waypoint: waypointYAML("assumption", "follow", `"1 == 1"`, loc(12, 3))},
		{name: "bool literal is not an identifier", waypoint: waypointYAML("assumption", "follow", `"true == false"`, loc(12, 3))},
		{name: "struct member", waypoint: waypointYAML("assumption", "follow", `"s.x == 5"`, loc(12, 3))},
		{name: "array element", waypoint: waypointYAML("assumption", "follow", `"a[0] == 5"`, loc(12, 3))},
		{name: "dereference", waypoint: waypointYAML("assumption", "follow", `"*p == 5"`, loc(12, 3))},
		{name: "result keyword of function_return", waypoint: waypointYAML("assumption", "follow", `"\\result == 5"`, loc(12, 3))},
		{name: "arithmetic on the literal side", waypoint: waypointYAML("assumption", "follow", `"x == 5 + 1"`, loc(12, 3))},
		{name: "cast on the literal side", waypoint: waypointYAML("assumption", "follow", `"x == (int)5"`, loc(12, 3))},
		{name: "hostile literal", waypoint: waypointYAML("assumption", "follow", `"x == 0; system(\"id\")"`, loc(12, 3))},
		{name: "hostile literal with call", waypoint: waypointYAML("assumption", "follow", `"x == f()"`, loc(12, 3))},
		{name: "string literal", waypoint: waypointYAML("assumption", "follow", `"x == \"a\""`, loc(12, 3))},
		{name: "trailing semicolon", waypoint: waypointYAML("assumption", "follow", `"x == 5;"`, loc(12, 3))},
		{name: "empty constraint", waypoint: waypointYAML("assumption", "follow", `""`, loc(12, 3))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w, err := ParseWitness(witnessYAML("", tt.waypoint), "p.c")
			if err != nil {
				t.Fatalf("ParseWitness must not fail on an assumption it cannot use: %v", err)
			}
			if !reflect.DeepEqual(w.Assumptions, tt.want) {
				t.Errorf("Assumptions = %+v, want %+v", w.Assumptions, tt.want)
			}
			if w.Counts.Assumption != 1 {
				t.Errorf("Counts.Assumption = %d, want 1 (skipped waypoints are still counted)", w.Counts.Assumption)
			}
			if len(w.Points) != 0 || len(w.Branchings) != 0 || len(w.Targets) != 0 {
				t.Errorf("an assumption must not produce other waypoints: %+v", w)
			}
		})
	}
}

func TestParseWitnessBranchings(t *testing.T) {
	tests := []struct {
		name     string
		waypoint string
		want     []Branching
	}{
		{
			name:     "true",
			waypoint: waypointYAML("branching", "follow", `"true"`, loc(7, 3)),
			want:     []Branching{{Loc: Location{7, 3}, Value: "true"}},
		},
		{
			name:     "false",
			waypoint: waypointYAML("branching", "follow", `"false"`, loc(7, 3)),
			want:     []Branching{{Loc: Location{7, 3}, Value: "false"}},
		},
		{
			name:     "unquoted YAML boolean",
			waypoint: waypointYAML("branching", "follow", `true`, loc(7, 3)),
			want:     []Branching{{Loc: Location{7, 3}, Value: "true"}},
		},
		{
			name:     "default",
			waypoint: waypointYAML("branching", "follow", `"default"`, loc(7, 3)),
			want:     []Branching{{Loc: Location{7, 3}, Value: "default"}},
		},
		{
			name:     "integer literal",
			waypoint: waypointYAML("branching", "follow", `"42"`, loc(7, 3)),
			want:     []Branching{{Loc: Location{7, 3}, Value: "42"}},
		},
		{
			name:     "unquoted YAML integer",
			waypoint: waypointYAML("branching", "follow", `42`, loc(7, 3)),
			want:     []Branching{{Loc: Location{7, 3}, Value: "42"}},
		},
		{
			name:     "negative integer literal",
			waypoint: waypointYAML("branching", "follow", `"-1"`, loc(7, 3)),
			want:     []Branching{{Loc: Location{7, 3}, Value: "-1"}},
		},
		{
			name:     "hexadecimal integer literal with suffix",
			waypoint: waypointYAML("branching", "follow", `"0x10UL"`, loc(7, 3)),
			want:     []Branching{{Loc: Location{7, 3}, Value: "0x10UL"}},
		},
		{
			name:     "value is trimmed",
			waypoint: waypointYAML("branching", "follow", `"  false \t"`, loc(7, 3)),
			want:     []Branching{{Loc: Location{7, 3}, Value: "false"}},
		},
		{
			name:     "column absent means unspecified",
			waypoint: waypointYAML("branching", "follow", `"true"`, "file_name: p.c, line: 7"),
			want:     []Branching{{Loc: Location{7, 0}, Value: "true"}},
		},
		{
			name:     "empty action counts as follow",
			waypoint: waypointYAML("branching", "", `"true"`, loc(7, 3)),
			want:     []Branching{{Loc: Location{7, 3}, Value: "true"}},
		},
		// Everything below is silently skipped.
		{name: "avoid action", waypoint: waypointYAML("branching", "avoid", `"true"`, loc(7, 3))},
		{name: "other file", waypoint: waypointYAML("branching", "follow", `"true"`, "file_name: q.c, line: 7, column: 3")},
		{name: "no constraint", waypoint: waypointYAML("branching", "follow", "", loc(7, 3))},
		{name: "line zero", waypoint: waypointYAML("branching", "follow", `"true"`, loc(0, 3))},
		{name: "negative column", waypoint: waypointYAML("branching", "follow", `"true"`, loc(7, -2))},
		{name: "upper-case boolean", waypoint: waypointYAML("branching", "follow", `"TRUE"`, loc(7, 3))},
		{name: "float literal", waypoint: waypointYAML("branching", "follow", `"1.5"`, loc(7, 3))},
		{name: "char literal", waypoint: waypointYAML("branching", "follow", `"'a'"`, loc(7, 3))},
		{name: "expression", waypoint: waypointYAML("branching", "follow", `"x == 1"`, loc(7, 3))},
		{name: "hostile value", waypoint: waypointYAML("branching", "follow", `"1; system(\"id\")"`, loc(7, 3))},
		{name: "empty value", waypoint: waypointYAML("branching", "follow", `""`, loc(7, 3))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w, err := ParseWitness(witnessYAML("", tt.waypoint), "p.c")
			if err != nil {
				t.Fatalf("ParseWitness must not fail on a branching it cannot use: %v", err)
			}
			if !reflect.DeepEqual(w.Branchings, tt.want) {
				t.Errorf("Branchings = %+v, want %+v", w.Branchings, tt.want)
			}
			if w.Counts.Branching != 1 {
				t.Errorf("Counts.Branching = %d, want 1 (skipped waypoints are still counted)", w.Counts.Branching)
			}
		})
	}
}

func TestParseWitnessTargets(t *testing.T) {
	tests := []struct {
		name     string
		waypoint string
		want     []Location
	}{
		{name: "line and column", waypoint: waypointYAML("target", "follow", "", loc(20, 5)), want: []Location{{20, 5}}},
		{name: "column zero", waypoint: waypointYAML("target", "follow", "", loc(20, 0)), want: []Location{{20, 0}}},
		{name: "column absent", waypoint: waypointYAML("target", "follow", "", "file_name: p.c, line: 20"), want: []Location{{20, 0}}},
		{name: "empty action counts as follow", waypoint: waypointYAML("target", "", "", loc(20, 5)), want: []Location{{20, 5}}},
		{name: "line zero is skipped", waypoint: waypointYAML("target", "follow", "", loc(0, 5))},
		{name: "negative line is skipped", waypoint: waypointYAML("target", "follow", "", loc(-3, 5))},
		{name: "negative column is skipped", waypoint: waypointYAML("target", "follow", "", loc(20, -1))},
		{name: "other file is skipped", waypoint: waypointYAML("target", "follow", "", "file_name: q.c, line: 20, column: 5")},
		{name: "avoid action is skipped", waypoint: waypointYAML("target", "avoid", "", loc(20, 5))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w, err := ParseWitness(witnessYAML("", tt.waypoint), "p.c")
			if err != nil {
				t.Fatalf("ParseWitness: %v", err)
			}
			if !reflect.DeepEqual(w.Targets, tt.want) {
				t.Errorf("Targets = %+v, want %+v", w.Targets, tt.want)
			}
			if w.Counts.Target != 1 {
				t.Errorf("Counts.Target = %d, want 1", w.Counts.Target)
			}
		})
	}
}

func TestParseWitnessToleratesThreadID(t *testing.T) {
	yaml := []byte(`- entry_type: violation_sequence
  metadata:
    format_version: "2.1"
    unknown_metadata_key: [1, 2, 3]
    task:
      specification: "G ! data-race"
      data_model: LP64
      some_future_key: { nested: true }
  content:
  - segment:
    - waypoint:
        type: function_enter
        action: follow
        thread_id: 0
        location: { file_name: p.c, line: 4, column: 30 }
  - segment:
    - waypoint:
        type: assumption
        action: follow
        thread_id: 1
        constraint: { value: "x == 3", format: c_expression }
        location: { file_name: p.c, line: 5, column: 3, function: worker, unknown_location_key: 1 }
  - segment:
    - waypoint:
        type: branching
        action: follow
        thread_id: 1
        some_future_key: "ignored"
        constraint: { value: "false" }
        location: { file_name: p.c, line: 6, column: 3 }
  - segment:
    - waypoint:
        type: function_return
        action: follow
        thread_id: 1
        constraint: { value: "\\result == 9", format: ext_c_expression }
        location: { file_name: p.c, line: 7, column: 33 }
  - segment:
    - waypoint:
        type: target
        action: follow
        thread_id: any
        location: { file_name: p.c, line: 8, column: 3 }
    - waypoint:
        type: target
        action: follow
        thread_id: "any"
        location: { file_name: p.c, line: 9 }
`)
	w, err := ParseWitness(yaml, "p.c")
	if err != nil {
		t.Fatalf("ParseWitness: %v", err)
	}
	want := &Witness{
		Specification:      "G ! data-race",
		DataModel:          "LP64",
		ViolationSequences: 1,
		Points:             []InjectionPoint{{Loc: Location{7, 33}, Value: "9"}},
		Assumptions:        []Assumption{{Loc: Location{5, 3}, Variable: "x", Value: "3"}},
		Branchings:         []Branching{{Loc: Location{6, 3}, Value: "false"}},
		Targets:            []Location{{8, 3}, {9, 0}},
		Counts:             WaypointCounts{FunctionReturn: 1, Assumption: 1, Branching: 1, FunctionEnter: 1, Target: 2},
	}
	if !reflect.DeepEqual(w, want) {
		t.Errorf("got  %+v\nwant %+v", w, want)
	}
}

func TestParseWitnessDocumentOrder(t *testing.T) {
	yaml := witnessYAML("",
		waypointYAML("assumption", "follow", `"b == 2"`, loc(30, 3)),
		waypointYAML("branching", "follow", `"true"`, loc(40, 3)),
		waypointYAML("assumption", "follow", `"a == 1"`, loc(10, 3)),
		waypointYAML("branching", "follow", `"false"`, loc(40, 3)),
		waypointYAML("function_return", "follow", `"\\result == 4"`, loc(50, 9)),
		waypointYAML("assumption", "follow", `"b == 3"`, loc(30, 3)),
		waypointYAML("function_return", "follow", `"\\result == 5"`, loc(20, 9)),
		waypointYAML("target", "follow", "", loc(60, 3)),
	)
	w, err := ParseWitness(yaml, "p.c")
	if err != nil {
		t.Fatalf("ParseWitness: %v", err)
	}
	wantAssumptions := []Assumption{
		{Loc: Location{30, 3}, Variable: "b", Value: "2"},
		{Loc: Location{10, 3}, Variable: "a", Value: "1"},
		{Loc: Location{30, 3}, Variable: "b", Value: "3"},
	}
	wantBranchings := []Branching{
		{Loc: Location{40, 3}, Value: "true"},
		{Loc: Location{40, 3}, Value: "false"},
	}
	wantPoints := []InjectionPoint{
		{Loc: Location{50, 9}, Value: "4"},
		{Loc: Location{20, 9}, Value: "5"},
	}
	if !reflect.DeepEqual(w.Assumptions, wantAssumptions) {
		t.Errorf("Assumptions = %+v, want %+v", w.Assumptions, wantAssumptions)
	}
	if !reflect.DeepEqual(w.Branchings, wantBranchings) {
		t.Errorf("Branchings = %+v, want %+v", w.Branchings, wantBranchings)
	}
	if !reflect.DeepEqual(w.Points, wantPoints) {
		t.Errorf("Points = %+v, want %+v", w.Points, wantPoints)
	}
	if !reflect.DeepEqual(w.Targets, []Location{{60, 3}}) {
		t.Errorf("Targets = %+v", w.Targets)
	}
}

// ParseWitness and Parse must agree on function_return points, counts and
// errors for every existing fixture. Parse reports a value outside the
// allowlist as an error, ParseWitness in Unsupported.
func TestParseWitnessAgreesWithParse(t *testing.T) {
	tests := []struct {
		file     string
		basename string
	}{
		{"symbiotic.yml", "unsafe-program-example.c"},
		{"symbiotic.yml", "different-program.c"},
		{"cpachecker.yml", "unsafe-program-example.c"},
		{"mixed-types.yml", "program.c"},
		{"multi-sequence.yml", "program.c"},
		{"malicious-witness.yml", "program.c"},
		{"bad-location.yml", "program.c"},
	}
	for _, tt := range tests {
		t.Run(tt.file+"/"+tt.basename, func(t *testing.T) {
			data := mustRead(t, tt.file)
			points, counts, perr := Parse(data, tt.basename)
			w, werr := ParseWitness(data, tt.basename)
			if werr == nil && w.Unsupported != "" {
				if perr == nil || perr.Error() != w.Unsupported {
					t.Errorf("Parse error = %v, want %q", perr, w.Unsupported)
				}
				return
			}
			if (perr == nil) != (werr == nil) {
				t.Fatalf("Parse error = %v, ParseWitness error = %v", perr, werr)
			}
			if perr != nil {
				if perr.Error() != werr.Error() {
					t.Errorf("error texts differ: %q vs %q", perr, werr)
				}
				if w != nil {
					t.Errorf("ParseWitness must return nil on error, got %+v", w)
				}
				return
			}
			if !reflect.DeepEqual(points, w.Points) {
				t.Errorf("Points differ: Parse %+v, ParseWitness %+v", points, w.Points)
			}
			if counts != w.Counts {
				t.Errorf("Counts differ: Parse %+v, ParseWitness %+v", counts, w.Counts)
			}
		})
	}
}

func TestParseWitnessCPAcheckerExample(t *testing.T) {
	w, err := ParseWitness(mustRead(t, "cpachecker.yml"), "unsafe-program-example.c")
	if err != nil {
		t.Fatalf("ParseWitness: %v", err)
	}
	if w.Specification != "G ! call(reach_error())" || w.DataModel != "ILP32" {
		t.Errorf("metadata: specification %q, data model %q", w.Specification, w.DataModel)
	}
	if len(w.Points) != 0 {
		t.Errorf("no function_return expected, got %+v", w.Points)
	}
	if len(w.Assumptions) < 2 ||
		w.Assumptions[0] != (Assumption{Loc: Location{15, 3}, Variable: "v", Value: "0"}) ||
		w.Assumptions[1] != (Assumption{Loc: Location{16, 3}, Variable: "s", Value: "0"}) {
		t.Errorf("Assumptions = %+v", w.Assumptions)
	}
	if len(w.Branchings) == 0 || w.Branchings[0] != (Branching{Loc: Location{11, 3}, Value: "false"}) {
		t.Errorf("Branchings = %+v", w.Branchings)
	}
	if len(w.Targets) != w.Counts.Target || len(w.Targets) == 0 {
		t.Errorf("Targets = %+v, Counts.Target = %d", w.Targets, w.Counts.Target)
	}
}

func TestParseWitnessErrors(t *testing.T) {
	tests := []struct {
		name    string
		yaml    []byte
		wantErr string
	}{
		{
			name:    "malformed YAML",
			yaml:    []byte("not: [valid yaml"),
			wantErr: "failed to parse witness YAML",
		},
		{
			name:    "function_return without column",
			yaml:    witnessYAML("", waypointYAML("function_return", "follow", `"\\result == 1"`, "file_name: p.c, line: 10")),
			wantErr: "invalid 1-based location",
		},
		{
			name:    "function_return with line zero",
			yaml:    witnessYAML("", waypointYAML("function_return", "follow", `"\\result == 1"`, loc(0, 45))),
			wantErr: "invalid 1-based location",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w, err := ParseWitness(tt.yaml, "p.c")
			if err == nil {
				t.Fatalf("expected an error containing %q, got witness %+v", tt.wantErr, w)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err, tt.wantErr)
			}
			if w != nil {
				t.Errorf("witness must be nil on error, got %+v", w)
			}
			// Parse keeps reporting the same failure.
			if _, _, perr := Parse(tt.yaml, "p.c"); perr == nil || perr.Error() != err.Error() {
				t.Errorf("Parse error = %v, want %v", perr, err)
			}
		})
	}
}

// A value outside the allowlist marks the witness as unsupported, also in
// another file. Parsing goes on so that the waypoints are still counted, and
// the first such value is reported.
func TestParseWitnessUnsupported(t *testing.T) {
	tests := []struct {
		name string
		yaml []byte
		want string
	}{
		{
			name: "hostile function_return literal",
			yaml: witnessYAML("", waypointYAML("function_return", "follow", `"\\result == 0; system(\"id\")"`, loc(10, 45))),
			want: `witness constraint value "\\result == 0; system(\"id\")" at "p.c":10:45 is not an allowed C literal`,
		},
		{
			name: "hostile function_return literal in another file",
			yaml: witnessYAML("", waypointYAML("function_return", "follow", `"\\result == f()"`, "file_name: q.c, line: 10, column: 45")),
			want: `witness constraint value "\\result == f()" at "q.c":10:45 is not an allowed C literal`,
		},
		{
			name: "first of two",
			yaml: witnessYAML("",
				waypointYAML("function_return", "follow", `"\\result == 1"`, loc(9, 45)),
				waypointYAML("function_return", "follow", `"\\result == f()"`, loc(10, 45)),
				waypointYAML("function_return", "follow", `"\\result == g()"`, loc(11, 45)),
				waypointYAML("target", "follow", "", loc(12, 3)),
			),
			want: `witness constraint value "\\result == f()" at "p.c":10:45 is not an allowed C literal`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w, err := ParseWitness(tt.yaml, "p.c")
			if err != nil {
				t.Fatalf("ParseWitness: %v", err)
			}
			if !strings.HasPrefix(w.Unsupported, tt.want) {
				t.Errorf("Unsupported = %q, want prefix %q", w.Unsupported, tt.want)
			}
			for _, p := range w.Points {
				if p.Value != "1" {
					t.Errorf("value outside the allowlist extracted: %+v", p)
				}
			}
		})
	}
	w, err := ParseWitness(tests[2].yaml, "p.c")
	if err != nil {
		t.Fatal(err)
	}
	if w.Counts.FunctionReturn != 3 || w.Counts.Target != 1 {
		t.Errorf("Counts = %+v, want all waypoints counted", w.Counts)
	}
}

func TestParseKeepsCountsOnError(t *testing.T) {
	yaml := witnessYAML("",
		waypointYAML("assumption", "follow", `"x == 5"`, loc(3, 3)),
		waypointYAML("function_return", "follow", `"\\result == 1"`, loc(0, 45)),
	)
	points, counts, err := Parse(yaml, "p.c")
	if err == nil {
		t.Fatal("expected an error")
	}
	if points != nil {
		t.Errorf("points must be nil on error, got %+v", points)
	}
	if counts.Assumption != 1 || counts.FunctionReturn != 1 {
		t.Errorf("counts up to the failing waypoint must be kept: %+v", counts)
	}
}

func TestParseAssumption(t *testing.T) {
	tests := []struct {
		in       string
		variable string
		value    string
		ok       bool
	}{
		{"x == 5", "x", "5", true},
		{"5 == x", "x", "5", true},
		{"x==5", "x", "5", true},
		{"( x == 5 )", "x", "5", true},
		{"x == +5", "x", "+5", true},
		{"x == 5U", "x", "5U", true},
		{"x == '\\n'", "x", "'\\n'", true},
		{"x == '='", "x", "'='", true},
		{"'=' == x", "x", "'='", true},
		{"false == flag", "flag", "0", true},
		{"flag == true", "flag", "1", true},
		{"(true == flag)", "flag", "1", true},
		{"x == 5)", "", "", false},
		{"(x == 5", "", "", false},
		{"() == 5", "", "", false},
		{"x ==", "", "", false},
		{"== 5", "", "", false},
		{"x == 5 // c", "", "", false},
		{"x == 5\n&& y", "", "", false},
		{"x == true == y", "", "", false},
		{"9x == 5", "", "", false},
		{"x == y", "", "", false},
		{"false == true", "", "", false},
		{"", "", "", false},
	}
	for _, tt := range tests {
		variable, value, ok := parseAssumption(tt.in)
		if variable != tt.variable || value != tt.value || ok != tt.ok {
			t.Errorf("parseAssumption(%q) = (%q, %q, %v), want (%q, %q, %v)",
				tt.in, variable, value, ok, tt.variable, tt.value, tt.ok)
		}
	}
}
