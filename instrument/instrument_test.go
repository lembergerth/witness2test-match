// This file is part of witness2test,
// a tool to turn SV-COMP violation witnesses (format v2) into executable tests.
// https://gitlab.com/sosy-lab/software/witness2test
//
// SPDX-FileCopyrightText: 2026 Dirk Beyer <https://www.sosy-lab.org>
//
// SPDX-License-Identifier: Apache-2.0

package instrument

import (
	"strconv"
	"strings"
	"testing"

	"witness2test/witness"
)

func TestCollectNondetCallsBasic(t *testing.T) {
	src := "int main() {\n  int x = __VERIFIER_nondet_int();\n  return x;\n}\n"
	sites := CollectNondetCalls(src)
	if len(sites) != 1 {
		t.Fatalf("want 1 site, got %d", len(sites))
	}
	// Line: "  int x = __VERIFIER_nondet_int();" → ')' is at 1-based col 33.
	if sites[0].Line != 2 || sites[0].ColumnOfClosingParen != 33 || sites[0].VariantShortName != "int" {
		t.Errorf("got %+v", sites[0])
	}
}

func TestCollectNondetCallsSkipsDeclaration(t *testing.T) {
	src := "extern int __VERIFIER_nondet_int();\nint main() { int x = __VERIFIER_nondet_int(); }\n"
	sites := CollectNondetCalls(src)
	if len(sites) != 1 {
		t.Fatalf("want 1 site (the call, not the declaration), got %d: %+v", len(sites), sites)
	}
	if sites[0].Line != 2 {
		t.Errorf("call should be on line 2, got line %d", sites[0].Line)
	}
}

func TestCollectNondetCallsDeclarationAndCallOnSameLine(t *testing.T) {
	src := "extern int __VERIFIER_nondet_int(); int x = __VERIFIER_nondet_int();\n"
	sites := CollectNondetCalls(src)
	if len(sites) != 1 {
		t.Fatalf("want 1 site on the same line (only the call), got %d: %+v", len(sites), sites)
	}
	// Line: "extern int __VERIFIER_nondet_int(); int x = __VERIFIER_nondet_int();"
	// The call's ')' is at 1-based column 67.
	if sites[0].ColumnOfClosingParen != 67 {
		t.Errorf("ColumnOfClosingParen = %d, want 67", sites[0].ColumnOfClosingParen)
	}
}

func TestCollectNondetCallsMultipleOnSameLine(t *testing.T) {
	src := "int z = __VERIFIER_nondet_int() + __VERIFIER_nondet_int();\n"
	sites := CollectNondetCalls(src)
	if len(sites) != 2 {
		t.Fatalf("want 2 sites, got %d", len(sites))
	}
	if sites[0].ColumnOfClosingParen >= sites[1].ColumnOfClosingParen {
		t.Errorf("sites should be in source order: %+v", sites)
	}
}

func TestCollectNondetCallsVariantShortName(t *testing.T) {
	src := "int main() {\n  unsigned char c = __VERIFIER_nondet_uchar();\n}\n"
	sites := CollectNondetCalls(src)
	if len(sites) != 1 || sites[0].VariantShortName != "uchar" {
		t.Fatalf("variant: %+v", sites)
	}
}

func TestInstrumentSingleSite(t *testing.T) {
	src := "int main() {\n  int x = __VERIFIER_nondet_int();\n  return x;\n}\n"
	sites := CollectNondetCalls(src)
	injections := map[witness.Location][]string{
		{Line: 2, Column: 33}: {"42"},
	}
	out, err := Instrument(src, injections, sites, nil)
	if err != nil {
		t.Fatalf("Instrument: %v", err)
	}
	if !strings.Contains(out, "__VERIFIER_nondet_value_injection_2_33()") {
		t.Error("output should contain the renamed call")
	}
	if strings.Contains(out, "int x = __VERIFIER_nondet_int()") {
		t.Error("output should not contain the original call")
	}
	if !strings.Contains(out, "static const int values[] = { 42 };") {
		t.Error("output should contain the injection function values array")
	}
	if !strings.Contains(out, "_Exit(214);") {
		t.Error("overflow branch must call _Exit(214) — exitcodes.WitnessInconsistent")
	}
}

func TestInstrumentMultipleSitesSameLine(t *testing.T) {
	src := "int main() {\n  int z = __VERIFIER_nondet_int() + __VERIFIER_nondet_int();\n}\n"
	sites := CollectNondetCalls(src)
	if len(sites) != 2 {
		t.Fatalf("expected 2 sites, got %d", len(sites))
	}
	injections := map[witness.Location][]string{
		{Line: sites[0].Line, Column: sites[0].ColumnOfClosingParen}: {"1"},
		{Line: sites[1].Line, Column: sites[1].ColumnOfClosingParen}: {"2"},
	}
	out, err := Instrument(src, injections, sites, nil)
	if err != nil {
		t.Fatalf("Instrument: %v", err)
	}
	// Both call sites must be renamed and the source line should still contain both.
	rewritten := out
	if !strings.Contains(rewritten, "__VERIFIER_nondet_value_injection_2_") {
		t.Error("expected at least one renamed call on line 2")
	}
	// The two renamed call sites must use distinct column suffixes.
	first := "__VERIFIER_nondet_value_injection_" + strconv.Itoa(sites[0].Line) + "_" + strconv.Itoa(sites[0].ColumnOfClosingParen)
	second := "__VERIFIER_nondet_value_injection_" + strconv.Itoa(sites[1].Line) + "_" + strconv.Itoa(sites[1].ColumnOfClosingParen)
	if !strings.Contains(out, first+"()") || !strings.Contains(out, second+"()") {
		t.Errorf("expected both renamed calls present: %q and %q", first, second)
	}
}

func TestInstrumentUnmatchedLocationErrors(t *testing.T) {
	src := "int main() {\n  int x = __VERIFIER_nondet_int();\n}\n"
	sites := CollectNondetCalls(src)
	injections := map[witness.Location][]string{
		{Line: 99, Column: 5}: {"42"},
	}
	_, err := Instrument(src, injections, sites, nil)
	if err == nil {
		t.Fatal("expected mismatch error")
	}
	if !strings.Contains(err.Error(), "99:5") {
		t.Errorf("error should name unmatched location: %v", err)
	}
}

func TestInstrumentWitnessOnDeclarationErrors(t *testing.T) {
	// Declaration's closing paren is at col 34; call's closing paren at col 67.
	src := "extern int __VERIFIER_nondet_int(); int x = __VERIFIER_nondet_int();\n"
	sites := CollectNondetCalls(src)
	if len(sites) != 1 {
		t.Fatalf("setup: expected 1 site, got %d", len(sites))
	}
	declCol := 34 // closing-paren column of the declaration, not the call
	injections := map[witness.Location][]string{
		{Line: 1, Column: declCol}: {"42"},
	}
	_, err := Instrument(src, injections, sites, nil)
	if err == nil {
		t.Fatal("expected error: witness location should not match a declaration")
	}
}

func TestInstrumentTypeNameExpansion(t *testing.T) {
	src := "int main() {\n  unsigned char c = __VERIFIER_nondet_uchar();\n}\n"
	sites := CollectNondetCalls(src)
	injections := map[witness.Location][]string{
		{Line: sites[0].Line, Column: sites[0].ColumnOfClosingParen}: {"0xff"},
	}
	out, err := Instrument(src, injections, sites, nil)
	if err != nil {
		t.Fatalf("Instrument: %v", err)
	}
	if !strings.Contains(out, "unsigned char __VERIFIER_nondet_value_injection_") {
		t.Error("uchar should expand to unsigned char in the generated definition")
	}
	if !strings.Contains(out, "static const unsigned char values[] = { 0xff };") {
		t.Error("values array should use the expanded type")
	}
}

func TestInstrumentIdempotenceOnEmptyInjections(t *testing.T) {
	src := "int main() {\n  int x = __VERIFIER_nondet_int();\n}\n"
	sites := CollectNondetCalls(src)
	out, err := Instrument(src, nil, sites, nil)
	if err != nil {
		t.Fatalf("Instrument: %v", err)
	}
	if out != src {
		t.Errorf("with no injections, output should equal input.\ngot:\n%s\n", out)
	}
}

func TestInstrumentIdempotenceOnAlreadyInstrumented(t *testing.T) {
	src := "int main() {\n  int x = __VERIFIER_nondet_value_injection_2_30();\n}\n"
	sites := CollectNondetCalls(src)
	if len(sites) != 0 {
		t.Fatalf("already-instrumented source should have no nondet sites left, got %d", len(sites))
	}
	out, err := Instrument(src, nil, sites, nil)
	if err != nil {
		t.Fatalf("Instrument: %v", err)
	}
	if out != src {
		t.Error("re-instrumenting already-instrumented source should be a no-op")
	}
}

func TestCollectReachErrorSkipsDefinition(t *testing.T) {
	src := "void reach_error(){}\nint main(){ reach_error(); return 0; }\n"
	sites := CollectReachErrorCalls(src)
	if len(sites) != 1 {
		t.Fatalf("want 1 reach_error call (not the definition), got %d: %+v", len(sites), sites)
	}
	if sites[0].Line != 2 {
		t.Errorf("call should be on line 2, got %d", sites[0].Line)
	}
}

func TestCollectReachErrorMultipleSites(t *testing.T) {
	src := "void reach_error(void);\nint main(){ reach_error(); reach_error(); return 0; }\n"
	sites := CollectReachErrorCalls(src)
	if len(sites) != 2 {
		t.Fatalf("want 2 reach_error calls, got %d", len(sites))
	}
}

func TestInstrumentRewritesReachError(t *testing.T) {
	src := "void reach_error(){}\nint main(){ reach_error(); return 0; }\n"
	sites := CollectNondetCalls(src)
	reachSites := CollectReachErrorCalls(src)
	out, err := Instrument(src, nil, sites, reachSites)
	if err != nil {
		t.Fatalf("Instrument: %v", err)
	}
	if !strings.Contains(out, "__VERIFIER_w2t_reach_error()") {
		t.Error("instrumented source should contain the wrapper call")
	}
	if !strings.Contains(out, "_Exit(213)") {
		t.Error("wrapper definition should call _Exit(213)")
	}
	// The definition `void reach_error(){}` must be preserved (only calls are rewritten).
	if !strings.Contains(out, "void reach_error(){}") {
		t.Error("the function definition itself must not be rewritten")
	}
}

func TestActualFunctionTypeFromShortName(t *testing.T) {
	cases := map[string]string{
		"int":      "int",
		"uchar":    "unsigned char",
		"uint":     "unsigned int",
		"ulong":    "unsigned long",
		"u8":       "unsigned char",
		"bool":     "_Bool",
		"longlong": "long long",
		"pointer":  "void *",
		"size_t":   "unsigned int",
		"unknown":  "unknown",
	}
	for in, want := range cases {
		got := actualFunctionTypeFromShortName(in)
		if got != want {
			t.Errorf("%s → %s, want %s", in, got, want)
		}
	}
}

