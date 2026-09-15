// This file is part of witness2test,
// a tool to turn SV-COMP violation witnesses (format v2) into executable tests.
// https://gitlab.com/sosy-lab/software/witness2test
//
// SPDX-FileCopyrightText: 2026 Dirk Beyer <https://www.sosy-lab.org>
//
// SPDX-License-Identifier: Apache-2.0

package witness

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func mustRead(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return data
}

func TestParseSymbioticExample(t *testing.T) {
	data := mustRead(t, "symbiotic.yml")
	got, counts, err := Parse(data, "unsafe-program-example.c")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := []InjectionPoint{
		{Loc: Location{Line: 10, Column: 45}, Value: "2"},
		{Loc: Location{Line: 18, Column: 33}, Value: "1"},
		{Loc: Location{Line: 18, Column: 33}, Value: "255"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	if counts.FunctionReturn != 3 || counts.Target != 1 {
		t.Errorf("counts: function_return=%d target=%d (want 3 and 1)", counts.FunctionReturn, counts.Target)
	}
}

func TestParseMalformedYAML(t *testing.T) {
	_, _, err := Parse([]byte("not: [valid yaml"), "program.c")
	if err == nil {
		t.Fatal("expected error for malformed YAML")
	}
	if !strings.Contains(err.Error(), "parse") {
		t.Errorf("error should mention parsing: %v", err)
	}
}

func TestParseRejectsHostileLiteral(t *testing.T) {
	data := mustRead(t, "malicious-witness.yml")
	_, _, err := Parse(data, "program.c")
	if err == nil {
		t.Fatal("hostile constraint value must be rejected")
	}
	if !strings.Contains(err.Error(), "not an allowed C literal") {
		t.Errorf("error should explain rejection: %v", err)
	}
	if !strings.Contains(err.Error(), "program.c:10:45") {
		t.Errorf("error should locate the offending waypoint: %v", err)
	}
}

func TestParseFiltersWaypointTypesAndActions(t *testing.T) {
	data := mustRead(t, "mixed-types.yml")
	got, counts, err := Parse(data, "program.c")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := []InjectionPoint{
		{Loc: Location{Line: 10, Column: 45}, Value: "0xff"},
		{Loc: Location{Line: 18, Column: 33}, Value: "-3"},
		{Loc: Location{Line: 22, Column: 33}, Value: "1.5f"},
		{Loc: Location{Line: 24, Column: 33}, Value: "'A'"},
		{Loc: Location{Line: 25, Column: 33}, Value: "true"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	if counts.FunctionReturn != 6 { // 5 follow + 1 avoid
		t.Errorf("function_return count = %d, want 6", counts.FunctionReturn)
	}
	if counts.Assumption != 1 || counts.Branching != 1 || counts.FunctionEnter != 1 || counts.Target != 1 {
		t.Errorf("waypoint counts wrong: %+v", counts)
	}
}

func TestParseMultipleSequences(t *testing.T) {
	data := mustRead(t, "multi-sequence.yml")
	got, _, err := Parse(data, "program.c")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := []InjectionPoint{
		{Loc: Location{Line: 10, Column: 45}, Value: "1"},
		{Loc: Location{Line: 18, Column: 33}, Value: "2"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestParseBasenameMismatchReturnsEmpty(t *testing.T) {
	data := mustRead(t, "symbiotic.yml")
	got, counts, err := Parse(data, "different-program.c")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty slice for basename mismatch, got %d points", len(got))
	}
	if counts.FunctionReturn == 0 {
		t.Error("counts should still reflect waypoints scanned")
	}
}

func TestParseAssumptionOnlyWitness(t *testing.T) {
	data := mustRead(t, "cpachecker.yml")
	got, counts, err := Parse(data, "unsafe-program-example.c")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("CPAchecker witness has no function_return, expected empty, got %+v", got)
	}
	if counts.Assumption == 0 {
		t.Error("expected non-zero assumption count")
	}
}

func TestParseRejectsInvalidLocation(t *testing.T) {
	data := mustRead(t, "bad-location.yml")
	_, _, err := Parse(data, "program.c")
	if err == nil {
		t.Fatal("expected error for line=0 location")
	}
	if !strings.Contains(err.Error(), "invalid 1-based location") {
		t.Errorf("error should mention invalid location: %v", err)
	}
}

func TestGroupByLocation(t *testing.T) {
	in := []InjectionPoint{
		{Loc: Location{18, 33}, Value: "1"},
		{Loc: Location{10, 45}, Value: "2"},
		{Loc: Location{18, 33}, Value: "255"},
	}
	got := GroupByLocation(in)
	if !reflect.DeepEqual(got[Location{18, 33}], []string{"1", "255"}) {
		t.Errorf("18:33 group preserved order: %v", got[Location{18, 33}])
	}
	if !reflect.DeepEqual(got[Location{10, 45}], []string{"2"}) {
		t.Errorf("10:45 group: %v", got[Location{10, 45}])
	}
}

func TestGroupByLocationEmpty(t *testing.T) {
	if GroupByLocation(nil) != nil {
		t.Error("nil input should yield nil map")
	}
}

func TestIsAllowedLiteral(t *testing.T) {
	allowed := []string{
		"0", "42", "-3", "+7", "0xff", "0XFF", "0b1011", "0755",
		"42u", "42UL", "42ull", "1.0", ".5", "1.5e-3", "1.5f", "1.5L",
		"-1.0e10", "'a'", "'\\n'", "'\\\\'", "'\\x1f'", "true", "false",
	}
	for _, v := range allowed {
		if !isAllowedLiteral(v) {
			t.Errorf("expected %q to be allowed", v)
		}
	}
	rejected := []string{
		"", " ", "42; system()", "0 + 1", "foo()", "\"a\"", "0/*x*/", "{0}",
		"\\result", "x", "0; }", "1.5fx",
	}
	for _, v := range rejected {
		if isAllowedLiteral(v) {
			t.Errorf("expected %q to be rejected", v)
		}
	}
}

func TestWaypointCountsSummary(t *testing.T) {
	zero := WaypointCounts{}
	if zero.Summary() != "no waypoints" {
		t.Errorf("empty counts: %q", zero.Summary())
	}
	full := WaypointCounts{FunctionReturn: 2, Assumption: 1, Branching: 1, FunctionEnter: 1, Target: 1, Other: 1}
	s := full.Summary()
	for _, want := range []string{"function_return=2", "assumption=1", "branching=1", "function_enter=1", "target=1", "other=1"} {
		if !strings.Contains(s, want) {
			t.Errorf("summary missing %q: %s", want, s)
		}
	}
}
