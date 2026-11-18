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
	"testing"

	"witness2test/witness"
)

func TestResolveMissingColumns(t *testing.T) {
	src := "int main() {\n" +
		"  int x = __VERIFIER_nondet_int();\n" + // line 2, ')' at 33
		"  int y = __VERIFIER_nondet_int() + __VERIFIER_nondet_int();\n" + // line 3, two calls
		"  return x + y;\n" + // line 4, no call
		"}\n"
	sites := CollectNondetCalls(src)
	point := func(line, column int, value string) witness.InjectionPoint {
		return witness.InjectionPoint{Loc: witness.Location{Line: line, Column: column}, Value: value}
	}
	tests := []struct {
		name        string
		points      []witness.InjectionPoint
		want        []witness.InjectionPoint
		unsupported string
	}{
		{"single call on the line", []witness.InjectionPoint{point(2, 0, "1")}, []witness.InjectionPoint{point(2, 33, "1")}, ""},
		// The order of the values is kept, also when only some of them give
		// the column.
		{"mixed with column", []witness.InjectionPoint{point(2, 33, "1"), point(2, 0, "2"), point(2, 33, "3")},
			[]witness.InjectionPoint{point(2, 33, "1"), point(2, 33, "2"), point(2, 33, "3")}, ""},
		{"with column is kept", []witness.InjectionPoint{point(3, 33, "1")}, []witness.InjectionPoint{point(3, 33, "1")}, ""},
		// Without a nondet call, the waypoint is on the call of another
		// function; it stays unmatched.
		{"no call on the line", []witness.InjectionPoint{point(4, 0, "1")}, []witness.InjectionPoint{point(4, 0, "1")}, ""},
		{"two calls on the line", []witness.InjectionPoint{point(2, 0, "1"), point(3, 0, "2"), point(3, 0, "3")}, nil,
			"function_return waypoint at line 3 has no column, and the line has 2 __VERIFIER_nondet_X() calls"},
		{"no points", nil, nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, unsupported := resolveMissingColumns(tt.points, sites)
			if unsupported != tt.unsupported {
				t.Fatalf("unsupported = %q, want %q", unsupported, tt.unsupported)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("points = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestResolveMissingColumnsKeepsInput(t *testing.T) {
	sites := CollectNondetCalls("int x = __VERIFIER_nondet_int();\n")
	points := []witness.InjectionPoint{{Loc: witness.Location{Line: 1}, Value: "1"}}
	resolveMissingColumns(points, sites)
	if points[0].Loc.Column != 0 {
		t.Errorf("input changed: %v", points)
	}
}
