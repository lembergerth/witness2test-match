// This file is part of witness2test-match,
// a tool to turn SV-COMP violation witnesses (format v2) into executable tests.
// https://github.com/lembergerth/witness2test-match
//
// SPDX-FileCopyrightText: 2026 Thomas Lemberger <https://thomaslemberger.com>
//
// SPDX-License-Identifier: Apache-2.0

package witness

import (
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestIsAllowedLiteralIntegerSuffix(t *testing.T) {
	// C17 6.4.4.1: u, l, ll, ul, ull, lu, llu. The case of u and of l/ll is
	// free, but ll is not written lL or Ll.
	allowed := []string{
		"42u", "42U", "42l", "42L", "42ll", "42LL",
		"42ul", "42uL", "42Ul", "42UL", "42ull", "42uLL", "42Ull", "42ULL",
		"42lu", "42lU", "42Lu", "42LU", "42llu", "42llU", "42LLu", "42LLU",
		"0x10uLL", "0b11LU", "0755l", "0u", "-1ll", "+1ULL",
	}
	for _, v := range allowed {
		if !isAllowedLiteral(v) {
			t.Errorf("expected %q to be allowed", v)
		}
	}
	rejected := []string{
		"42uu", "42UU", "42uU", "42lul", "42ulu", "42LUL", "42lll", "42LLL",
		"42lL", "42Ll", "42ulL", "42uLl", "42lLu", "42Llu", "42luu", "42ullu",
		"42uuu", "42lu l", "0x10lL", "42z", "42ui",
	}
	for _, v := range rejected {
		if isAllowedLiteral(v) {
			t.Errorf("expected %q to be rejected", v)
		}
	}
}

func TestIsAllowedLiteralFloat(t *testing.T) {
	allowed := []string{
		"1.0", ".5", "1.", "1e3", "1E3", "1e+3", "1.0f", "1.0F", "1e-3L", "1.f",
		"1.l", ".5e2", "0.0", "00.5", "09.5", "08e1", "-1.", "+.5f", "1e3f",
	}
	for _, v := range allowed {
		if !isAllowedLiteral(v) {
			t.Errorf("expected %q to be allowed", v)
		}
	}
	// A digit sequence without a fraction and without an exponent is an
	// integer, and must be a valid one.
	rejected := []string{
		"08", "09", "0129", "1f", "1F", "0f", "08L", "123f", "-1f",
		"1e", "1e+", "1.e", ".", ".f", "e3", ".e3", "1.0ff", "1.0lf", "1..0", "1.0e3.0",
	}
	for _, v := range rejected {
		if isAllowedLiteral(v) {
			t.Errorf("expected %q to be rejected", v)
		}
	}
}

func TestIsAllowedLiteralCharacter(t *testing.T) {
	allowed := []string{
		`'a'`, `'Z'`, `'0'`, `' '`, `'~'`, `'!'`, `'"'`, `'?'`, `'['`, `']'`, `'&'`, `'('`,
		`'\n'`, `'\r'`, `'\t'`, `'\0'`, `'\''`, `'\"'`, `'\\'`, `'\x1f'`, `'\xFF'`, `'\x7'`,
	}
	for _, v := range allowed {
		if !isAllowedLiteral(v) {
			t.Errorf("expected %q to be allowed", v)
		}
	}
	rejected := []string{
		`''`, `'''`, `'\'`, `'ab'`, `'a`, `a'`,
		// Raw control characters.
		"'\x00'", "'\x01'", "'\t'", "'\n'", "'\r'", "'\x1b'", "'\x1f'", "'\x7f'",
		// Not ASCII: a two-byte and a three-byte character, and bytes that
		// are not valid UTF-8.
		"'\u00e9'", "'\u20ac'", "'\x80'", "'\xff'", "'\xc3'",
		// Escape sequences outside the allowlist.
		`'\a'`, `'\x'`, `'\x123'`, `'\777'`, `'\u00e9'`, `'\U000000e9'`,
	}
	for _, v := range rejected {
		if isAllowedLiteral(v) {
			t.Errorf("expected %q to be rejected", v)
		}
	}
	// Every single byte between the quotes.
	for c := 0; c < 256; c++ {
		v := "'" + string([]byte{byte(c)}) + "'"
		want := c >= 0x20 && c <= 0x7e && c != '\'' && c != '\\'
		if got := isAllowedLiteral(v); got != want {
			t.Errorf("isAllowedLiteral(%q) = %v, want %v", v, got, want)
		}
	}
}

func TestIsAllowedLiteralLength(t *testing.T) {
	tests := []struct {
		literal string
		want    bool
	}{
		{"1" + strings.Repeat("0", 63), true},
		{"1" + strings.Repeat("0", 64), false},
		{"-" + strings.Repeat("7", 63), true},
		{"-" + strings.Repeat("7", 64), false},
		{"0x" + strings.Repeat("f", 62), true},
		{"0x" + strings.Repeat("f", 63), false},
		{"1." + strings.Repeat("0", 62), true},
		{"1." + strings.Repeat("0", 63), false},
		{strings.Repeat("9", 100000), false},
	}
	for _, tt := range tests {
		if got := isAllowedLiteral(tt.literal); got != tt.want {
			t.Errorf("isAllowedLiteral(literal of %d characters, %.10s...) = %v, want %v",
				len(tt.literal), tt.literal, got, tt.want)
		}
	}
}

func TestParseWitnessFunctionReturnValues(t *testing.T) {
	tests := []struct {
		constraint string // the YAML scalar
		want       string
	}{
		{`"\\result == 5"`, "5"},
		{`"\\result == 5llu"`, "5llu"},
		{`"\\result == 1.f"`, "1.f"},
		{`"\\result == ' '"`, "' '"},
		// The generated C is compiled without <stdbool.h>.
		{`"\\result == true"`, "1"},
		{`"\\result == false"`, "0"},
		{`"\\result == ` + strings.Repeat("7", 64) + `"`, strings.Repeat("7", 64)},
	}
	for _, tt := range tests {
		t.Run(tt.constraint, func(t *testing.T) {
			yaml := witnessYAML("", waypointYAML("function_return", "follow", tt.constraint, loc(10, 45)))
			want := []InjectionPoint{{Loc: Location{10, 45}, Value: tt.want}}
			w, err := ParseWitness(yaml, "p.c")
			if err != nil {
				t.Fatalf("ParseWitness: %v", err)
			}
			if !reflect.DeepEqual(w.Points, want) {
				t.Errorf("Points = %+v, want %+v", w.Points, want)
			}
			points, _, err := Parse(yaml, "p.c")
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if !reflect.DeepEqual(points, want) {
				t.Errorf("Parse points = %+v, want %+v", points, want)
			}
		})
	}
}

// A function_return value outside the allowlist is not extracted, and the
// witness is marked as unsupported.
func TestParseWitnessRejectsFunctionReturnValues(t *testing.T) {
	tests := []struct {
		name       string
		constraint string // the YAML scalar
	}{
		{"literal of 65 characters", `"\\result == ` + strings.Repeat("7", 65) + `"`},
		{"huge literal", `"\\result == ` + strings.Repeat("7", 100000) + `"`},
		{"invalid octal literal", `"\\result == 08"`},
		{"float suffix on an integer", `"\\result == 1f"`},
		{"invalid integer suffix", `"\\result == 1lul"`},
		{"repeated integer suffix", `"\\result == 1uu"`},
		{"control character in a character literal", `"\\result == '\a'"`},
		{"non-ASCII character literal", `"\\result == '\u00e9'"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			yaml := witnessYAML("", waypointYAML("function_return", "follow", tt.constraint, loc(10, 45)))
			w, err := ParseWitness(yaml, "p.c")
			if err != nil {
				t.Fatalf("ParseWitness: %s", short(err))
			}
			if len(w.Points) != 0 {
				t.Errorf("Points = %s, want none", short(w.Points))
			}
			if !strings.Contains(w.Unsupported, "not an allowed C literal") {
				t.Errorf("Unsupported %s does not say that the literal is not allowed", short(w.Unsupported))
			}
		})
	}
}

// A constraint with a line break does not have the shape "\result == <value>"
// at all. As before, nothing is extracted from it.
func TestParseWitnessSkipsFunctionReturnWithLineBreak(t *testing.T) {
	for _, constraint := range []string{`"\\result == '\n'"`, `"\\result == 5\n; system(\"id\")"`} {
		yaml := witnessYAML("", waypointYAML("function_return", "follow", constraint, loc(10, 45)))
		w, err := ParseWitness(yaml, "p.c")
		if err != nil {
			t.Fatalf("%s: ParseWitness: %v", constraint, err)
		}
		if len(w.Points) != 0 {
			t.Errorf("%s: Points = %+v, want none", constraint, w.Points)
		}
	}
}

// short formats v for a failure message. Some of the values are huge.
func short(v any) string {
	s := fmt.Sprintf("%+v", v)
	if len(s) > 200 {
		return s[:200] + "..."
	}
	return s
}

// Assumption and branching waypoints with a value outside the allowlist are
// skipped silently.
func TestParseWitnessSkipsValuesOutsideAllowlist(t *testing.T) {
	sixtyFour := strings.Repeat("7", 64)
	tests := []struct {
		name           string
		typ            string
		constraint     string // the YAML scalar
		wantAssumption *Assumption
		wantBranching  *Branching
	}{
		{name: "assumption with false", typ: "assumption", constraint: `"false == b"`,
			wantAssumption: &Assumption{Loc: Location{12, 3}, Variable: "b", Value: "0"}},
		{name: "assumption with literal of 64 characters", typ: "assumption", constraint: `"x == ` + sixtyFour + `"`,
			wantAssumption: &Assumption{Loc: Location{12, 3}, Variable: "x", Value: sixtyFour}},
		{name: "assumption with literal of 64 characters first", typ: "assumption", constraint: `"` + sixtyFour + ` == x"`,
			wantAssumption: &Assumption{Loc: Location{12, 3}, Variable: "x", Value: sixtyFour}},
		{name: "assumption with literal of 65 characters", typ: "assumption", constraint: `"x == 7` + sixtyFour + `"`},
		{name: "assumption with literal of 65 characters first", typ: "assumption", constraint: `"7` + sixtyFour + ` == x"`},
		{name: "assumption with huge literal", typ: "assumption", constraint: `"x == ` + strings.Repeat("7", 100000) + `"`},
		{name: "assumption with invalid octal literal", typ: "assumption", constraint: `"x == 08"`},
		{name: "assumption with float suffix on an integer", typ: "assumption", constraint: `"x == 1f"`},
		{name: "assumption with invalid integer suffix", typ: "assumption", constraint: `"x == 5lul"`},
		{name: "assumption with control character in a character literal", typ: "assumption", constraint: `"x == '\e'"`},
		{name: "assumption with non-ASCII character literal", typ: "assumption", constraint: `"x == '\u00e9'"`},

		{name: "branching with literal of 64 characters", typ: "branching", constraint: `"` + sixtyFour + `"`,
			wantBranching: &Branching{Loc: Location{12, 3}, Value: sixtyFour}},
		{name: "branching with valid suffix", typ: "branching", constraint: `"5llu"`,
			wantBranching: &Branching{Loc: Location{12, 3}, Value: "5llu"}},
		{name: "branching with literal of 65 characters", typ: "branching", constraint: `"7` + sixtyFour + `"`},
		{name: "branching with huge literal", typ: "branching", constraint: `"` + strings.Repeat("7", 100000) + `"`},
		{name: "branching with invalid integer suffix", typ: "branching", constraint: `"5uu"`},
		{name: "branching with invalid octal literal", typ: "branching", constraint: `"08"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w, err := ParseWitness(witnessYAML("", waypointYAML(tt.typ, "follow", tt.constraint, loc(12, 3))), "p.c")
			if err != nil {
				t.Fatalf("ParseWitness must not fail: %s", short(err))
			}
			var wantAssumptions []Assumption
			if tt.wantAssumption != nil {
				wantAssumptions = []Assumption{*tt.wantAssumption}
			}
			var wantBranchings []Branching
			if tt.wantBranching != nil {
				wantBranchings = []Branching{*tt.wantBranching}
			}
			if !reflect.DeepEqual(w.Assumptions, wantAssumptions) {
				t.Errorf("Assumptions = %s, want %s", short(w.Assumptions), short(wantAssumptions))
			}
			if !reflect.DeepEqual(w.Branchings, wantBranchings) {
				t.Errorf("Branchings = %s, want %s", short(w.Branchings), short(wantBranchings))
			}
		})
	}
}

// The outcome of a branching is not a value that is embedded in C code.
func TestParseWitnessKeepsBranchingOutcomes(t *testing.T) {
	w, err := ParseWitness(witnessYAML("",
		waypointYAML("branching", "follow", `"true"`, loc(7, 3)),
		waypointYAML("branching", "follow", `"false"`, loc(7, 3)),
	), "p.c")
	if err != nil {
		t.Fatalf("ParseWitness: %v", err)
	}
	want := []Branching{{Loc: Location{7, 3}, Value: "true"}, {Loc: Location{7, 3}, Value: "false"}}
	if !reflect.DeepEqual(w.Branchings, want) {
		t.Errorf("Branchings = %+v, want %+v", w.Branchings, want)
	}
}

// File names and constraint values come from the witness. They must not be
// able to add lines or terminal escape sequences to a message.
func TestParseWitnessErrorsQuoteWitnessContent(t *testing.T) {
	// YAML double-quoted scalar and what %q makes of its value.
	const hostileName = `"dir\n\e[31mFAKE ERROR\e[0m\r/p.c"`
	const quotedName = `"dir\n\x1b[31mFAKE ERROR\x1b[0m\r/p.c"`
	tests := []struct {
		name string
		yaml []byte
		want []string
	}{
		{
			name: "literal outside the allowlist",
			yaml: witnessYAML("", waypointYAML("function_return", "follow", `"\\result == 0;\r\e[2Jsystem(\"id\")"`,
				"file_name: "+hostileName+", line: 10, column: 45")),
			want: []string{
				`witness constraint value "\\result == 0;\r\x1b[2Jsystem(\"id\")" at ` + quotedName + `:10:45 is`,
				"not an allowed C literal",
			},
		},
		{
			name: "invalid location",
			yaml: witnessYAML("", waypointYAML("function_return", "follow", `"\\result == 1"`,
				"file_name: "+hostileName+", line: 0, column: 45")),
			want: []string{
				"witness waypoint at " + quotedName + " has",
				"invalid 1-based location (line=0, column=45)",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// A value outside the allowlist is reported in the witness,
			// an invalid location as an error.
			w, err := ParseWitness(tt.yaml, "p.c")
			var msg string
			switch {
			case err != nil:
				msg = err.Error()
			case w.Unsupported != "":
				msg = w.Unsupported
			default:
				t.Fatal("expected an error or an unsupported value")
			}
			for _, r := range msg {
				if r < 0x20 || r == 0x7f {
					t.Errorf("error message contains the control character %q: %q", r, msg)
					break
				}
			}
			for _, want := range tt.want {
				if !strings.Contains(msg, want) {
					t.Errorf("error message %q does not contain %q", msg, want)
				}
			}
		})
	}
}

func TestParseWitnessViolationSequences(t *testing.T) {
	const sequence = "- entry_type: violation_sequence\n  content: []\n"
	const invariants = "- entry_type: invariant_set\n  content: []\n"
	tests := []struct {
		name string
		yaml string
		want int
	}{
		{name: "empty document", yaml: "", want: 0},
		{name: "comment only", yaml: "# nothing\n", want: 0},
		{name: "empty sequence", yaml: "[]\n", want: 0},
		{name: "correctness witness", yaml: invariants, want: 0},
		{name: "entry without entry_type", yaml: "- content: []\n", want: 0},
		{name: "entry type in other case", yaml: "- entry_type: Violation_Sequence\n  content: []\n", want: 0},
		{name: "one violation sequence", yaml: sequence, want: 1},
		{name: "two violation sequences", yaml: sequence + sequence, want: 2},
		{name: "mixed entries", yaml: invariants + sequence + invariants + sequence + sequence, want: 3},
		{
			name: "violation sequence with waypoints",
			yaml: string(witnessYAML("", waypointYAML("target", "follow", "", loc(3, 1)))),
			want: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w, err := ParseWitness([]byte(tt.yaml), "p.c")
			if err != nil {
				t.Fatalf("ParseWitness: %v (the caller decides what a witness without violation sequence means)", err)
			}
			if w.ViolationSequences != tt.want {
				t.Errorf("ViolationSequences = %d, want %d", w.ViolationSequences, tt.want)
			}
		})
	}
}

func TestParseWitnessEntryTypes(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want []string
	}{
		{name: "empty document", yaml: "", want: nil},
		{name: "empty sequence", yaml: "[]\n", want: nil},
		{name: "entry without entry_type", yaml: "- content: []\n", want: []string{""}},
		{
			name: "mixed entries",
			yaml: "- entry_type: invariant_set\n  content: []\n- entry_type: violation_sequence\n  content: []\n- entry_type: Violation_Sequence\n",
			want: []string{"invariant_set", "violation_sequence", "Violation_Sequence"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w, err := ParseWitness([]byte(tt.yaml), "p.c")
			if err != nil {
				t.Fatalf("ParseWitness: %v", err)
			}
			if !reflect.DeepEqual(w.EntryTypes, tt.want) {
				t.Errorf("EntryTypes = %q, want %q", w.EntryTypes, tt.want)
			}
		})
	}
}

func TestParseWitnessViolationSequencesOfFixtures(t *testing.T) {
	for name, want := range map[string]int{"symbiotic.yml": 1, "multi-sequence.yml": 2} {
		w, err := ParseWitness(mustRead(t, name), "program.c")
		if err != nil {
			t.Fatalf("%s: ParseWitness: %v", name, err)
		}
		if w.ViolationSequences != want {
			t.Errorf("%s: ViolationSequences = %d, want %d", name, w.ViolationSequences, want)
		}
	}
}

// The decoder quotes the offending scalar in its messages. That is content of
// the witness as well.
func TestParseWitnessYAMLErrorIsPrintable(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want []string
	}{
		{
			name: "scalar of the wrong type",
			yaml: "- entry_type: violation_sequence\n  content:\n  - segment:\n" +
				"    - waypoint: { type: target, location: { file_name: p.c, line: \"\\e[31mX\\nY\" } }\n",
			want: []string{"failed to parse witness YAML: ", "line 4: cannot unmarshal !!str `\\x1b[31mX\\nY` into int"},
		},
		{
			name: "two scalars of the wrong type",
			yaml: "- entry_type: violation_sequence\n  content:\n  - segment:\n" +
				"    - waypoint: { type: target, location: { file_name: p.c, line: \"\\rA\", column: \"\\u202eB\" } }\n",
			want: []string{"failed to parse witness YAML: ", "`\\rA` into int", "`\\u202eB` into int"},
		},
		{
			name: "syntax error",
			yaml: "not: [valid yaml",
			want: []string{"failed to parse witness YAML: yaml: "},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w, err := ParseWitness([]byte(tt.yaml), "p.c")
			if err == nil {
				t.Fatalf("expected an error, got witness %s", short(w))
			}
			msg := err.Error()
			for _, r := range msg {
				if !strconv.IsPrint(r) {
					t.Errorf("error message contains the non-printable character %q: %q", r, msg)
					break
				}
			}
			for _, want := range tt.want {
				if !strings.Contains(msg, want) {
					t.Errorf("error message %q does not contain %q", msg, want)
				}
			}
			// The error of the decoder stays available to callers.
			if unwrapped := errors.Unwrap(err); unwrapped == nil || !strings.HasPrefix(unwrapped.Error(), "yaml: ") {
				t.Errorf("errors.Unwrap = %v, want the error of the YAML decoder", unwrapped)
			}
		})
	}
}
